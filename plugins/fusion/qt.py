#!/usr/bin/env python3
import threading
import time
import weakref

from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electroncash.plugins import hook
from electroncash.i18n import _, ngettext, pgettext
from electroncash.util import print_error, profiler, PrintError, Weak, format_satoshis_plain, finalization_print_error, InvalidPassword
from electroncash.wallet import Abstract_Wallet
from electroncash_gui.qt.util import EnterButton, CancelButton, Buttons, CloseButton, HelpLabel, OkButton, rate_limited, AppModalDialog, WaitingDialog, WindowModalDialog
from electroncash_gui.qt.main_window import ElectrumWindow, StatusBarButton

from .fusion import can_fuse_from, can_fuse_to, DEFAULT_SELF_FUSE
from .server import FusionServer, Params
from .plugin import FusionPlugin, TOR_PORTS, is_tor_port, server_list, get_upnp, DEFAULT_SELECTOR, COIN_FRACTION_FUDGE_FACTOR, select_coins, DEFAULT_QUEUED_AUTOFUSE, DEFAULT_AUTOFUSE_CONFIRMED_ONLY

from pathlib import Path
heredir = Path(__file__).parent
icon_fusion_logo = QIcon(str(heredir / 'Cash Fusion Logo - No Text.svg'))
icon_fusion_logo_gray = QIcon(str(heredir / 'Cash Fusion Logo - No Text Gray.svg'))

class Plugin(FusionPlugin):
    utilwin = None
    settingswin = None
    initted = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs) # gives us self.config
        self.widgets = weakref.WeakSet() # widgets we made, that need to be hidden & deleted when plugin is disabled

    def on_close(self):
        super().on_close()
        # Shut down plugin.
        # This can be triggered from one wallet's window while
        # other wallets' windows have plugin-related modals open.
        self.active = False
        # TODO: disable auto-fusing
        for window in self.gui.windows:
            # this could be slow since it touches windows one by one... could optimize this by dispatching simultaneously.
            self.on_close_window(window)
        self.utilwin = None
        self.settingswin = None
        # Clean up
        for w in self.widgets:
            try:
                w.setParent(None)
                w.close()
                w.hide()
                w.deleteLater()
            except Exception:
                # could be <RuntimeError: wrapped C/C++ object of type SettingsDialog has been deleted> but really we just want to suppress all exceptions
                pass

    @hook
    def init_qt(self, gui):
        # This gets called when this plugin is initialized, but also when
        # any other plugin is initialized after us.
        if self.initted:
            return
        self.initted = True
        self.gui = gui

        # We also have to find which windows are already open, and make
        # them work with fusion.
        for window in self.gui.windows:
            self.on_new_window(window)

    @hook
    def address_list_context_menu_setup(self, address_list, menu, addrs):
        if not self.active:
            return
        wallet = address_list.wallet
        window = address_list.parent
        network = wallet.network
        if not (can_fuse_from(wallet) and can_fuse_to(wallet) and network):
            return
        if not hasattr(wallet, '_fusions'):
            # that's a bug... all wallets should have this
            return

        coins = wallet.get_utxos(addrs, exclude_frozen=True, mature=True, confirmed_only=True, exclude_slp=True)

        def start_fusion():
            def do_it(password):
                try:
                    with wallet.lock:
                        if not hasattr(wallet, '_fusions'):
                            return
                        fusion = self.start_fusion(wallet, password, coins)
                except RuntimeError as e:
                    window.show_error(_('CashFusion failed: {error_message}').format(error_message=str(e)))
                    return
                window.show_message(ngettext("One coin has been sent to CashFusion for fusing.",
                                             "{count} coins have been sent to CashFusion for fusing.",
                                             len(coins)).format(count=len(coins)))

            has_pw, password = Plugin.get_cached_pw(wallet)
            if has_pw and password is None:
                d = PasswordDialog(wallet, _("Enter your password to fuse these coins"), do_it)
                d.show()
            else:
                do_it(password)

        if coins:
            menu.addAction(ngettext("Input one coin to CashFusion", "Input {count} coins to CashFusion", len(coins)).format(count = len(coins)),
                           start_fusion)

    @hook
    def on_new_window(self, window):
        # Called on initial plugin load (if enabled) and every new window; only once per window.
        wallet = window.wallet

        if not (can_fuse_from(wallet) and can_fuse_to(wallet)):
            # don't do anything with non-fusable wallets
            # (if inter-wallet fusing is added, this should change.)
            return

        want_autofuse = wallet.storage.get('cashfusion_autofuse', False)
        self.add_wallet(wallet, window.gui_object.get_cached_password(wallet))

        if want_autofuse and not self.is_autofusing(wallet):
            def callback(password):
                self.enable_autofusing(wallet, password)
                button = window._cashfusion_button()
                button.update_state()
            d = PasswordDialog(wallet, _("Previously you had auto-fusion enabled on this wallet. If you would like to keep auto-fusing in the background, enter your password."),
                               callback_ok = callback)
            d.show()
            self.widgets.add(d)

        # bit of a dirty hack, to insert our status bar icon (always using index 4, should put us just after the password-changer icon)
        sb = window.statusBar()
        sbbtn = FusionButton(self, wallet)
        sb.insertPermanentWidget(4, sbbtn)
        self.widgets.add(sbbtn)
        window._cashfusion_button = weakref.ref(sbbtn)

    @hook
    def on_close_window(self, window):
        # Invoked when closing wallet or entire application
        # Also called by on_close, above.
        wallet = window.wallet

        fusions = self.remove_wallet(wallet)
        if not fusions:
            return

        for f in fusions:
            f.stop('Closing wallet')

        # Soft-stop background fuse if running.
        # We avoid doing a hard disconnect in the middle of a fusion round.
        def task():
            for f in fusions:
                f.join()
        d = WaitingDialog(window.top_level_window(), _('Shutting down active CashFusions (may take a minute to finish)'), task)
        d.exec_()

    @hook
    def on_new_password(self, window, old, new):
        wallet = window.wallet
        if self.is_autofusing(wallet):
            try:
                self.enable_autofusing(wallet, new)
                self.print_error(wallet, "updated autofusion password")
            except InvalidPassword:
                self.disable_autofusing(wallet)
                self.print_error(wallet, "disabled autofusion due to incorrect password - BUG")

    def show_util_window(self, ):
        if self.utilwin is None:
            # keep a singleton around
            self.utilwin = UtilWindow(self)
            self.widgets.add(self.utilwin)
        self.utilwin.show()
        self.utilwin.raise_()

    def requires_settings(self):
        # called from main_window.py internal_plugins_dialog
        return True
    def settings_widget(self, window):
        # called from main_window.py internal_plugins_dialog
        btn = QPushButton(_('Settings'))
        btn.clicked.connect(self.show_settings_dialog)
        return btn

    def show_settings_dialog(self, ):
        if self.settingswin is None:
            # keep a singleton around
            self.settingswin = SettingsDialog(self, self.config)
            self.widgets.add(self.settingswin)
        self.settingswin.show()
        self.settingswin.raise_()

    @classmethod
    def window_for_wallet(cls, wallet):
        ''' Convenience: Given a wallet instance, derefernces the weak_window
        attribute of the wallet and returns a strong reference to the window.
        May return None if the window is gone (deallocated).  '''
        assert isinstance(wallet, Abstract_Wallet)
        return (wallet.weak_window and wallet.weak_window()) or None

    @classmethod
    def get_suitable_dialog_window_parent(cls, wallet_or_window):
        ''' Convenience: Given a wallet or a window instance, return a suitable
        'top level window' parent to use for dialog boxes. '''
        if isinstance(wallet_or_window, Abstract_Wallet):
            wallet = wallet_or_window
            window = cls.window_for_wallet(wallet)
            return (window and window.top_level_window()) or None
        elif isinstance(wallet_or_window, ElectrumWindow):
            window = wallet_or_window
            return window.top_level_window()
        else:
            raise TypeError(f"Expected a wallet or a window instance, instead got {type(wallet_or_window)}")

    @classmethod
    def get_cached_pw(cls, wallet):
        ''' Will return a tuple: (bool, password) for the given wallet.  The
        boolean is whether the wallet is password protected and the second
        item is the cached password, if it's known, otherwise None if it is not
        known.  If the wallet has no password protection the tuple is always
        (False, None). '''
        if not wallet.has_password():
            return False, None
        window = cls.window_for_wallet(wallet)
        if not window:
            raise RuntimeError(f'Wallet {wallet.diagnostic_name()} lacks a valid ElectrumWindow instance!')
        pw = window.gui_object.get_cached_password(wallet)
        if pw is not None:
            try:
                wallet.check_password(pw)
            except InvalidPassword:
                pw = None
        return True, pw

    @classmethod
    def cache_pw(cls, wallet, password):
        window = cls.window_for_wallet(wallet)
        if window:
            window.gui_object.cache_password(wallet, password)



class PasswordDialog(WindowModalDialog):
    """ Slightly fancier password dialog -- can be used non-modal (asynchronous) and has internal password checking.
    To run non-modally, use .show with the callbacks; to run modally, use .run. """
    def __init__(self, wallet, message, callback_ok = None, callback_cancel = None):
        parent = Plugin.get_suitable_dialog_window_parent(wallet)
        super().__init__(parent=parent, title=_("Enter Password"))
        self.setWindowIcon(icon_fusion_logo)
        self.wallet = wallet
        self.callback_ok = callback_ok
        self.callback_cancel = callback_cancel
        self.password = None

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        msglabel = QLabel(message)
        msglabel.setWordWrap(True)
        hbox = QHBoxLayout()
        iconlabel = QLabel(); iconlabel.setPixmap(icon_fusion_logo.pixmap(32))
        hbox.addWidget(iconlabel)
        hbox.addWidget(msglabel)
        cmargins = hbox.contentsMargins(); cmargins.setBottom(10); hbox.setContentsMargins(cmargins)  # pad the bottom a bit
        vbox.addLayout(hbox)
        self.pwle = QLineEdit()
        self.pwle.setEchoMode(2)
        vbox.addWidget(self.pwle)
        self.badpass = QLabel("<i>" + _("Incorrect password entered. Please try again.") + "</i>")
        qs = QSizePolicy()
        qs.setRetainSizeWhenHidden(True)
        self.badpass.setSizePolicy(qs)
        vbox.addWidget(self.badpass)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(CancelButton(self))
        okbutton = OkButton(self)
        okbutton.clicked.disconnect()
        okbutton.clicked.connect(self.pw_entered)
        buttons.addWidget(okbutton)
        vbox.addLayout(buttons)

        self.badpass.hide()

    def _on_pw_ok(self, password):
        self.password = password
        Plugin.cache_pw(self.wallet, password)  # to remember it for a time so as to not keep bugging the user
        self.accept()
        if self.callback_ok:
            self.callback_ok(password)

    def _chk_pass(self, password):
        pw_ok = not self.wallet.has_password()
        if not pw_ok:
            try:
                self.wallet.check_password(password)
                pw_ok = True
            except InvalidPassword:
                pass
        return pw_ok

    def pw_entered(self, ):
        password = self.pwle.text()
        if self._chk_pass(password):
            self._on_pw_ok(password)
        else:
            self.badpass.show()
            self.pwle.clear()
            self.pwle.setFocus()

    def closeEvent(self, event):
        super().closeEvent(self)
        if event.isAccepted():
            if not self.result() and self.callback_cancel:
                self.callback_cancel(self)
            self.setParent(None)
            self.deleteLater()

    def run(self):
        self.exec_()
        return self.password


class FusionButton(StatusBarButton):
    def __init__(self, plugin, wallet):
        super().__init__(QIcon(), 'Fusion', self.toggle_autofuse)

        self.plugin = plugin
        self.wallet = wallet

        self.icon_autofusing_on = icon_fusion_logo
        self.icon_autofusing_off = icon_fusion_logo_gray
        self.icon_fusing_problem = self.style().standardIcon(QStyle.SP_MessageBoxWarning)

#        title = QWidgetAction(self)
#        title.setDefaultWidget(QLabel("<i>" + _("CashFusion") + "</i>"))
        self.action_toggle = QAction(_("Auto-fuse in background"))
        self.action_toggle.setCheckable(True)
        self.action_toggle.triggered.connect(self.toggle_autofuse)
        action_separator1 = QAction(self); action_separator1.setSeparator(True)
        action_wsettings = QAction(_("Wallet settings..."), self)
        action_wsettings.triggered.connect(self.show_wallet_settings)
        action_settings = QAction(_("CashFusion settings..."), self)
        action_settings.triggered.connect(self.plugin.show_settings_dialog)
        action_separator2 = QAction(self); action_separator2.setSeparator(True)
        action_util = QAction(_("Fusions..."), self)
        action_util.triggered.connect(self.plugin.show_util_window)

        self.addActions([self.action_toggle, action_separator1,
                         action_wsettings, action_settings,
                         action_separator2, action_util])

        self.setContextMenuPolicy(Qt.ActionsContextMenu)

        self.update_state()

    def update_state(self):
        autofuse = self.plugin.is_autofusing(self.wallet)
        self.action_toggle.setChecked(autofuse)
        if autofuse:
            self.setIcon(self.icon_autofusing_on)
            self.setToolTip(_('CashFusion is fusing in background'))
        else:
            self.setIcon(self.icon_autofusing_off)
            self.setToolTip(_('CashFusion is paused'))

    def toggle_autofuse(self):
        autofuse = self.plugin.is_autofusing(self.wallet)
        if not autofuse:
            has_pw, password = Plugin.get_cached_pw(self.wallet)
            if has_pw and password is None:
                # Fixme: See if we can not use a blocking password dialog here.
                password = PasswordDialog(self.wallet, _("To perform auto-fusing in background, enter your password.")).run()
                if password is None:
                    return
            try:
                self.plugin.enable_autofusing(self.wallet, password)
            except InvalidPassword:
                ''' Somehow the password changed from underneath us. Silenty ignore. '''
        else:
            running = self.plugin.disable_autofusing(self.wallet)
            if running:
                res = QMessageBox.question(Plugin.get_suitable_dialog_window_parent(self.wallet),
                                           _("Disabling automatic Cash Fusions"),
                                           _("New automatic fusions will not be started, but you have {num} currently in progress."
                                             " Would you like to signal them to stop?").format(num=len(running)) )
                if res == QMessageBox.Yes:
                    for f in running:
                        f.stop('Stop requested by user')
        self.update_state()

    def show_wallet_settings(self):
        win = getattr(self.wallet, '_cashfusion_settings_window', None)
        if not win:
            win = WalletSettingsDialog(Plugin.get_suitable_dialog_window_parent(self.wallet),
                                       self.plugin, self.wallet)
        win.show()
        win.raise_()


class SettingsDialog(QDialog):
    torscanthread = None
    torscanthread_update = pyqtSignal(object)

    def __init__(self, plugin, config):
        super().__init__()
        self.plugin = plugin
        self.config = config
        self.torscanthread_ping = threading.Event()
        self.torscanthread_update.connect(self.torport_update)

        self.setWindowTitle(_("CashFusion - Settings"))
        self.setWindowIcon(icon_fusion_logo)
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        box = QGroupBox(_("Network")) ; main_layout.addWidget(box)
        slayout = QVBoxLayout() ; box.setLayout(slayout)

        grid = QGridLayout() ; slayout.addLayout(grid)

        grid.addWidget(QLabel(_("Server")), 0, 0)
        hbox = QHBoxLayout(); grid.addLayout(hbox, 0, 1)
        self.combo_server_host = QComboBox()
        self.combo_server_host.setEditable(True)
        self.combo_server_host.setInsertPolicy(QComboBox.NoInsert)
        self.combo_server_host.setCompleter(None)
        self.combo_server_host.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.combo_server_host.activated.connect(self.combo_server_activated)
        self.combo_server_host.lineEdit().textEdited.connect(self.user_changed_server)
        self.combo_server_host.addItems([f'{s[0]} ({s[1]}{" - ssl" if s[2] else ""})' for s in server_list])
        hbox.addWidget(self.combo_server_host)
        hbox.addWidget(QLabel(_("P:")))
        self.le_server_port = QLineEdit()
        self.le_server_port.setMaximumWidth(50)
        self.le_server_port.textEdited.connect(self.user_changed_server)
        hbox.addWidget(self.le_server_port)
        self.cb_server_ssl = QCheckBox(_('SSL'))
        self.cb_server_ssl.clicked.connect(self.user_changed_server)
        hbox.addWidget(self.cb_server_ssl)

        grid.addWidget(QLabel(_("Tor")), 1, 0)
        hbox = QHBoxLayout(); grid.addLayout(hbox, 1, 1)
        self.le_tor_host = QLineEdit('localhost')
        self.le_tor_host.textEdited.connect(self.user_edit_torhost)
        hbox.addWidget(self.le_tor_host)
        hbox.addWidget(QLabel(_("P:")))
        self.le_tor_port = QLineEdit()
        self.le_tor_port.setMaximumWidth(50)
        self.le_tor_port.setValidator(QIntValidator(0, 65535))
        self.le_tor_port.textEdited.connect(self.user_edit_torport)
        hbox.addWidget(self.le_tor_port)
        self.l_tor_status = QLabel()
        hbox.addWidget(self.l_tor_status)
        self.b_tor_refresh = QPushButton()
        self.b_tor_refresh.clicked.connect(self.torscanthread_ping.set)
        self.b_tor_refresh.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        hbox.addWidget(self.b_tor_refresh)
        self.cb_tor_auto = QCheckBox(_('autodetect'))
        self.cb_tor_auto.clicked.connect(self.cb_tor_auto_clicked)
        hbox.addWidget(self.cb_tor_auto)

        btn = QPushButton(_("Fusions..."))
        btn.clicked.connect(self.plugin.show_util_window)
        main_layout.addLayout(Buttons(btn, CloseButton(self)))

        self.pm_good_proxy = QIcon(":icons/status_connected_proxy.svg").pixmap(24)
        self.pm_bad_proxy = QIcon(":icons/status_disconnected.svg").pixmap(24)


        self.update_server()
        self.update_tor()

    def update_server(self):
        # called initially / when config changes
        host, port, ssl = self.plugin.get_server()
        try: # see if it's in default list, if so we can set it ...
            index = server_list.index((host,port,ssl))
        except ValueError: # not in list
            index = -1
        self.combo_server_host.setCurrentIndex(index)
        self.combo_server_host.setEditText(host)
        self.le_server_port.setText(str(port))
        self.cb_server_ssl.setChecked(ssl)

    def combo_server_activated(self, index):
        # only triggered when user selects a combo item
        self.plugin.set_server(*server_list[index])
        self.update_server()

    def user_changed_server(self, *args):
        # user edited the host / port / ssl
        host = self.combo_server_host.currentText()
        try:
            port = int(self.le_server_port.text())
        except ValueError:
            port = 0
        ssl = self.cb_server_ssl.isChecked()
        self.plugin.set_server(host, port, ssl)

    def update_tor(self,):
        # called on init an switch of auto
        autoport = self.plugin.has_auto_torport()
        host = self.plugin.get_torhost()
        port = self.plugin.get_torport()
        self.l_tor_status.clear()
        self.torport_update(port)
        self.cb_tor_auto.setChecked(autoport)
        self.le_tor_host.setEnabled(not autoport)
        self.le_tor_host.setText(str(host))
        self.le_tor_port.setEnabled(not autoport)
        if not autoport:
            self.le_tor_port.setText(str(port))

    def torport_update(self, goodport):
        # signalled from the tor checker thread
        autoport = self.plugin.has_auto_torport()
        port = self.plugin.get_torport()
        if autoport:
            sport = '?' if port is None else str(port)
            self.le_tor_port.setText(sport)
        if goodport is None:
            self.l_tor_status.setPixmap(self.pm_bad_proxy)
            if autoport:
                self.l_tor_status.setToolTip(_('Cannot find a Tor proxy on ports %(ports)s.')%dict(ports=TOR_PORTS))
            else:
                self.l_tor_status.setToolTip(_('Cannot find a Tor proxy on port %(port)d.')%dict(port=port))
        else:
            self.l_tor_status.setToolTip(_('Found a valid Tor proxy on this port.'))
            self.l_tor_status.setPixmap(self.pm_good_proxy)

    def user_edit_torhost(self, host):
        self.plugin.set_torhost(host)
        self.torscanthread_ping.set()

    def user_edit_torport(self, sport):
        try:
            port = int(sport)
        except ValueError:
            return
        self.plugin.set_torport(port)
        self.torscanthread_ping.set()

    def cb_tor_auto_clicked(self, state):
        self.plugin.set_torport('auto' if state else 'manual')
        port = self.plugin.get_torport()
        if port is not None:
            self.le_tor_port.setText(str(port))
        self.torscanthread_ping.set()
        self.update_tor()

    def showEvent(self, event):
        super().showEvent(event)
        if not event.isAccepted():
            return
        if self.torscanthread is None:
            self.torscanthread = threading.Thread(name='Fusion-scan_torport_settings', target=self.scan_torport_loop)
            self.torscanthread.daemon = True
            self.torscanthread_stopping = False
            self.torscanthread.start()

    def closeEvent(self, event):
        super().closeEvent(event)
        if not event.isAccepted():
            return
        self.torscanthread_stopping = True
        self.torscanthread_ping.set()
        self.torscanthread = None

    def scan_torport_loop(self, ):
        while not self.torscanthread_stopping:
            goodport = self.plugin.scan_torport()
            self.torscanthread_update.emit(goodport)
            self.torscanthread_ping.wait(10)
            self.torscanthread_ping.clear()


class WalletSettingsDialog(WindowModalDialog):
    def __init__(self, parent, plugin, wallet):
        super().__init__(parent=parent, title=_("CashFusion - Wallet Settings"))
        self.setWindowIcon(icon_fusion_logo)
        self.plugin = plugin
        self.wallet = wallet

        assert not hasattr(self.wallet, '_cashfusion_settings_window')
        self.wallet._cashfusion_settings_window = self

        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        box = QGroupBox(_("Auto-fusion coin selection")) ; main_layout.addWidget(box)
        slayout = QVBoxLayout() ; box.setLayout(slayout)

        grid = QGridLayout() ; slayout.addLayout(grid)

        self.radio_select_size = QRadioButton(_("Target typical output amount (sats)"))
        grid.addWidget(self.radio_select_size, 0, 0)
        self.radio_select_fraction = QRadioButton(_("Choose random fraction (0-1)"))
        grid.addWidget(self.radio_select_fraction, 1, 0)
        self.radio_select_count = QRadioButton(_("Target number of coins in wallet"))
        grid.addWidget(self.radio_select_count, 2, 0)

        self.radio_select_size.clicked.connect(self.edited_size)
        self.radio_select_fraction.clicked.connect(self.edited_fraction)
        self.radio_select_count.clicked.connect(self.edited_count)

        self.le_selector_size = QLineEdit()
        grid.addWidget(self.le_selector_size, 0, 1)
        self.le_selector_fraction = QLineEdit()
        grid.addWidget(self.le_selector_fraction, 1, 1)
        self.le_selector_count = QLineEdit()
        grid.addWidget(self.le_selector_count, 2, 1)

        self.le_selector_size.editingFinished.connect(self.edited_size)
        self.le_selector_fraction.editingFinished.connect(self.edited_fraction)
        self.le_selector_count.editingFinished.connect(self.edited_count)

        self.l_warn_selection = QLabel(_("Your target number of coins is low. In order to achieve the best consolidation, make sure that you have only 1 queued auto-fusion, and have 'self-fusing' set to 'No', and enable fusing only when all coins are confirmed."))
        self.l_warn_selection.setWordWrap(True)
        qs = QSizePolicy()
        qs.setRetainSizeWhenHidden(True)
        self.l_warn_selection.setSizePolicy(qs)
        slayout.addWidget(self.l_warn_selection)

        box = QGroupBox(_("Auto-fusion limits")) ; main_layout.addWidget(box)
        slayout = QVBoxLayout() ; box.setLayout(slayout)
        grid = QGridLayout() ; slayout.addLayout(grid)
        grid.addWidget(QLabel(_("Number of queued fusions")), 0, 0)
        self.le_queued_autofuse = QLineEdit()
        grid.addWidget(self.le_queued_autofuse, 0, 1)
        self.cb_autofuse_only_all_confirmed = QCheckBox(_("Only autofuse when all coins are confirmed"))
        slayout.addWidget(self.cb_autofuse_only_all_confirmed)

        self.le_queued_autofuse.editingFinished.connect(self.edited_queued_autofuse)
        self.cb_autofuse_only_all_confirmed.clicked.connect(self.clicked_confirmed_only)

        box = QGroupBox(_("Self-fusing")) ; main_layout.addWidget(box)
        slayout = QVBoxLayout() ; box.setLayout(slayout)

        slayout.addWidget(QLabel(_("Allow this wallet to participate multiply in the same fusion round?")))
        self.combo_self_fuse = QComboBox()
        self.combo_self_fuse.addItem(_('No'), 1)
        self.combo_self_fuse.addItem(_('Yes - as up to two players'), 2)
        slayout.addWidget(self.combo_self_fuse)

        self.combo_self_fuse.activated.connect(self.chose_self_fuse)

        main_layout.addLayout(Buttons(CloseButton(self)))

        self.update()

    def update(self):
        eligible, ineligible, sum_value, has_unconfirmed = select_coins(self.wallet)
        select_type, select_amount = self.wallet.storage.get('cashfusion_selector', DEFAULT_SELECTOR)
        self.le_selector_size.setEnabled(select_type == 'size')
        self.le_selector_fraction.setEnabled(select_type == 'fraction')
        self.le_selector_count.setEnabled(select_type == 'count')
        if select_type == 'size':
            self.radio_select_size.setChecked(True)
            sel_size = select_amount
            if sum_value > 0:
                sel_fraction = min(COIN_FRACTION_FUDGE_FACTOR * select_amount / sum_value, 1)
            else:
                sel_fraction = 1
        elif select_type == 'count':
            self.radio_select_count.setChecked(True)
            sel_size = max(sum_value / select_amount, 10000)
            sel_fraction = COIN_FRACTION_FUDGE_FACTOR / select_amount
        elif select_type == 'fraction':
            self.radio_select_fraction.setChecked(True)
            sel_size = max(sum_value * select_amount / COIN_FRACTION_FUDGE_FACTOR, 10000)
            sel_fraction = select_amount
        else:
            self.wallet.storage.put('cashfusion_selector', None)
            return self.update()
        sel_count = COIN_FRACTION_FUDGE_FACTOR / sel_fraction
        self.le_selector_size.setText(str(round(sel_size)))
        self.le_selector_fraction.setText('%.03f' % (sel_fraction))
        self.le_selector_count.setText(str(round(sel_count)))
        self.l_warn_selection.setVisible(sel_fraction > 0.2)

        self.le_queued_autofuse.setText(str(self.wallet.storage.get('cashfusion_queued_autofuse', DEFAULT_QUEUED_AUTOFUSE)))
        self.cb_autofuse_only_all_confirmed.setChecked(self.wallet.storage.get('cashfusion_autofuse_only_when_all_confirmed', DEFAULT_AUTOFUSE_CONFIRMED_ONLY))

        self.combo_self_fuse.setCurrentIndex(self.wallet.storage.get('cashfusion_self_fuse_players', DEFAULT_SELF_FUSE) - 1)

    def edited_size(self,):
        try:
            size = int(self.le_selector_size.text())
            if size < 10000:
                size = 10000
        except Exception as e:
            pass
        else:
            self.wallet.storage.put('cashfusion_selector', ('size', size))
        self.update()

    def edited_fraction(self,):
        try:
            fraction = float(self.le_selector_fraction.text())
            fraction = max(0., min(fraction, 1.))
        except Exception as e:
            pass
        else:
            self.wallet.storage.put('cashfusion_selector', ('fraction', round(fraction, 3)))
        self.update()

    def edited_count(self,):
        try:
            count = int(self.le_selector_count.text())
            if count < COIN_FRACTION_FUDGE_FACTOR:
                count = COIN_FRACTION_FUDGE_FACTOR
        except Exception as e:
            pass
        else:
            self.wallet.storage.put('cashfusion_selector', ('count', count))
        self.update()

    def edited_queued_autofuse(self,):
        try:
            numfuse = int(self.le_queued_autofuse.text())
            numfuse = max(1, min(numfuse, 10))
        except Exception as e:
            pass
        else:
            prevval = self.wallet.storage.get('cashfusion_queued_autofuse', DEFAULT_QUEUED_AUTOFUSE)
            self.wallet.storage.put('cashfusion_queued_autofuse', numfuse)
            if prevval > numfuse:
                for f in self.wallet._fusions_auto:
                    f.stop('User decreased queued-fuse limit', not_if_running = True)
        self.update()

    def clicked_confirmed_only(self, checked):
        self.wallet.storage.put('cashfusion_autofuse_only_when_all_confirmed', checked)
        self.update()

    def chose_self_fuse(self,):
        sel = self.combo_self_fuse.currentData()
        oldsel = self.wallet.storage.get('cashfusion_self_fuse_players', DEFAULT_SELF_FUSE)
        self.wallet.storage.put('cashfusion_self_fuse_players', sel)
        if oldsel != sel:
            for f in self.wallet._fusions:
                # we have to stop waiting fusions since the tags won't overlap.
                # otherwise, the user will end up self fusing way too much.
                f.stop('User changed self-fuse limit', not_if_running = True)
        self.update()

    def closeEvent(self, event):
        super().closeEvent(event)
        if not event.isAccepted():
            return
        self.setParent(None)
        del self.wallet._cashfusion_settings_window

class UtilWindow(QDialog):
    def __init__(self, plugin):
        super().__init__(parent=plugin.settingswin)
        self.plugin = plugin

        self.setWindowTitle("CashFusion - Fusions")
        self.setWindowIcon(icon_fusion_logo)

        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        clientbox = QGroupBox("Fusions")
        main_layout.addWidget(clientbox)

        self.serverbox = QGroupBox("Test server")
        main_layout.addWidget(self.serverbox)

        clayout = QVBoxLayout()
        clientbox.setLayout(clayout)

        self.t_active_fusions = QTreeWidget()
        self.t_active_fusions.setHeaderLabels(['wallet','status','status_ext'])
        self.t_active_fusions.setContextMenuPolicy(Qt.CustomContextMenu)
        self.t_active_fusions.customContextMenuRequested.connect(self.create_menu_active_fusions)
        self.t_active_fusions.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.t_active_fusions.itemDoubleClicked.connect(self.on_double_clicked)
        clayout.addWidget(self.t_active_fusions)


        slayout = QVBoxLayout()
        self.serverbox.setLayout(slayout)

        self.l_server_status = QLabel()
        slayout.addWidget(self.l_server_status)

        self.t_server_waiting = QTableWidget()
        self.t_server_waiting.setColumnCount(3)
        self.t_server_waiting.setRowCount(len(Params.tiers))
        self.t_server_waiting.setHorizontalHeaderLabels(['Tier (sats)','Num players', ''])
        for i, t in enumerate(Params.tiers):
            button = QPushButton("Start")
            button.clicked.connect(partial(self.clicked_start_fuse, t))
            self.t_server_waiting.setCellWidget(i, 2, button)
        slayout.addWidget(self.t_server_waiting)


        self.timer_status_update = QTimer(self)
        self.timer_status_update.setSingleShot(False)
        self.timer_status_update.timeout.connect(self.update_status)
        self.timer_status_update.start(2000)

        self.update_status()

        self.resize(520, 240)  # TODO: Have this somehow not be hard-coded

        self.show()

    def update_status(self):
        self.update_fusions()
        if self.plugin.testserver:
            self.l_server_status.setText(f'Test server status: ACTIVE {self.plugin.testserver.host}:{self.plugin.testserver.port}')
            table = self.t_server_waiting
            table.setRowCount(len(self.plugin.testserver.waiting_pools))
            for i,(t,pool) in enumerate(self.plugin.testserver.waiting_pools.items()):
                table.setItem(i,0,QTableWidgetItem(str(t)))
                table.setItem(i,1,QTableWidgetItem(str(len(pool.pool))))
            self.serverbox.show()
        else:
            self.serverbox.hide()

    def update_fusions(self):
        tree = self.t_active_fusions
        reselect_fusions = set(i.data(0, Qt.UserRole)() for i in tree.selectedItems())
        reselect_fusions.discard(None)
        reselect_items = []
        tree.clear()
        fusions_and_times = sorted(self.plugin.fusions.items(), key=lambda x:x[1], reverse=True)
        for fusion,t in fusions_and_times:
            wname = fusion.target_wallet.diagnostic_name()
            status, status_ext = fusion.status
            item = QTreeWidgetItem( [ wname, status, status_ext] )
            item.setToolTip(0, wname)  # this doesn't always fit in the column
            item.setToolTip(2, status_ext or '')  # neither does this
            item.setData(0, Qt.UserRole, weakref.ref(fusion))
            if fusion in reselect_fusions:
                reselect_items.append(item)
            tree.addTopLevelItem(item)
        for item in reselect_items:
            item.setSelected(True)

    def create_menu_active_fusions(self, position):
        selected = self.t_active_fusions.selectedItems()
        if not selected:
            return

        fusions = set(i.data(0, Qt.UserRole)() for i in selected)
        fusions.discard(None)
        statuses = set(f.status[0] for f in fusions)
        selection_of_1_fusion = list(fusions)[0] if len(fusions) == 1 else None
        has_live = 'running' in statuses or 'waiting' in statuses

        menu = QMenu()
        def cancel():
            for fusion in fusions:
                fusion.stop('Stop requested by user')
        if has_live:
            if 'running' in statuses:
                msg = _('Cancel (at end of round)')
            else:
                msg = _('Cancel')
            menu.addAction(msg, cancel)
        if selection_of_1_fusion and selection_of_1_fusion.txid:
            menu.addAction(_("View tx"), lambda: self._open_tx_for_fusion(selection_of_1_fusion))
        if not menu.isEmpty():
            menu.exec_(self.t_active_fusions.viewport().mapToGlobal(position))

    def on_double_clicked(self, item, column):
        self._open_tx_for_fusion( item.data(0, Qt.UserRole)() )

    def _open_tx_for_fusion(self, fusion):
        if not fusion or not fusion.txid or not fusion.target_wallet:
            return
        window = fusion.target_wallet.weak_window and fusion.target_wallet.weak_window()
        if window:
            tx = window.wallet.transactions.get(fusion.txid)
            if tx:
                window.show_transaction(tx, fusion.txlabel)
            else:
                window.show_error(_("Transaction not yet in wallet"))

    def clicked_start_fuse(self, tier, event):
        if self.plugin.testserver is None:
            return
        self.plugin.testserver.start_fuse(tier)
