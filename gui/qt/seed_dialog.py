#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from electroncash.i18n import _

from .util import *
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit


def seed_warning_msg(seed, has_der=False):
    der = (' ' + _('Additionally, save the derivation path as well.') + ' ') if has_der else ''
    return ''.join([
        "<p>",
        _("Please save these %d words on paper (order is important). "),
        der,
        _("This seed will allow you to recover your wallet in case "
          "of computer failure."),
        "</p>",
        "<b>" + _("WARNING") + ":</b>",
        "<ul>",
        "<li>" + _("Never disclose your seed.") + "</li>",
        "<li>" + _("Never type it on a website.") + "</li>",
        "<li>" + _("Do not store it electronically.") + "</li>",
        "</ul>"
    ]) % len(seed.split())


class SeedLayout(QVBoxLayout):
    #options
    is_bip39 = False
    is_ext = False
    is_bip39_145 = False

    def seed_options(self):
        dialog = QDialog()
        vbox = QVBoxLayout(dialog)
        if 'ext' in self.options:
            cb_ext = QCheckBox(_('Extend this seed with custom words') + " " + _("(aka 'passphrase')"))
            cb_ext.setChecked(self.is_ext)
            vbox.addWidget(cb_ext)
        if 'bip39' in self.options:
            def f(b):
                self.is_seed = (lambda x: bool(x)) if b else self.saved_is_seed
                self.is_bip39 = b
                self.on_edit()
                if b:
                    msg = ' '.join([
                        '<b>' + _('About BIP39') + ':</b>  ',
                        _('BIP39 seeds can be imported into Electron Cash so that users can access funds from other wallets.'),
                        _('However, we do not generate BIP39 seeds because our seed format is better at preserving future compatibility.'),
                        _('BIP39 seeds do not include a version number, which makes compatibility with future software more difficult.')
                    ])
                else:
                    msg = ''
                self.seed_warning.setText(msg)
            cb_bip39 = QCheckBox(_('BIP39 seed'))
            cb_bip39.toggled.connect(f)
            cb_bip39.setChecked(self.is_bip39)
            vbox.addWidget(cb_bip39)


        # Note: I grep'd the sources. As of May 2019, this code path cannot
        # be reached.  I'm leaving this here in case it serves some purpose
        # still -- but I cannot see any place in the code where this branch
        # would be triggered.  The below warning message is needlessly
        # FUD-ey.  It should be altered if this code path is ever reinstated.
        # -Calin
        if 'bip39_145' in self.options:
            def f(b):
                self.is_seed = (lambda x: bool(x)) if b else self.saved_is_seed
                self.on_edit()
                self.is_bip39 = b
                if b:
                    msg = ' '.join([
                        '<b>' + _('Warning') + ': BIP39 seeds are dangerous!' + '</b><br/><br/>',
                        _('BIP39 seeds can be imported in Electron Cash so that users can access funds locked in other wallets.'),
                        _('However, BIP39 seeds do not include a version number, which compromises compatibility with future wallet software.'),
                        '<br/><br/>',
                        _('We do not guarantee that BIP39 imports will always be supported in Electron Cash.'),
                        _('In addition, Electron Cash does not verify the checksum of BIP39 seeds; make sure you type your seed correctly.'),
                    ])
                else:
                    msg = ''
                self.seed_warning.setText(msg)
            cb_bip39_145 = QCheckBox(_('Use Coin Type 145 with bip39'))
            cb_bip39_145.toggled.connect(f)
            cb_bip39_145.setChecked(self.is_bip39_145)
            vbox.addWidget(cb_bip39_145)


        vbox.addLayout(Buttons(OkButton(dialog)))
        if not dialog.exec_():
            return None
        self.is_ext = cb_ext.isChecked() if 'ext' in self.options else False
        self.is_bip39 = cb_bip39.isChecked() if 'bip39' in self.options else False
        self.is_bip39_145 = cb_bip39_145.isChecked() if 'bip39_145' in self.options else False

    def __init__(self, seed=None, title=None, icon=True, msg=None, options=None, is_seed=None, passphrase=None, parent=None, editable=True,
                 derivation=None):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.options = options
        if title:
            self.addWidget(WWLabel(title))
        self.seed_e = ButtonsTextEdit()
        self.seed_e.setReadOnly(not editable)
        if seed:
            self.seed_e.setText(seed)
        else:
            self.seed_e.setTabChangesFocus(True)
            self.is_seed = is_seed
            self.saved_is_seed = self.is_seed
            self.seed_e.textChanged.connect(self.on_edit)
        self.seed_e.setMaximumHeight(75)
        hbox = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QIcon(":icons/seed.png").pixmap(64))
            logo.setMaximumWidth(60)
            hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        self.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.seed_type_label = QLabel('')
        hbox.addWidget(self.seed_type_label)
        if options:
            opt_button = EnterButton(_('Options'), self.seed_options)
            hbox.addWidget(opt_button)
            self.addLayout(hbox)
        grid_maybe = None
        grid_row = 0
        if passphrase:
            grid_maybe = QGridLayout()
            passphrase_e = QLineEdit()
            passphrase_e.setText(passphrase)
            passphrase_e.setReadOnly(True)
            grid_maybe.addWidget(QLabel(_("Your seed extension is") + ':'), grid_row, 0)
            grid_maybe.addWidget(passphrase_e, grid_row, 1)
            grid_row += 1
        if derivation:
            grid_maybe = grid_maybe or QGridLayout()
            der_e = QLineEdit()
            der_e.setText(str(derivation))
            der_e.setReadOnly(True)
            grid_maybe.addWidget(QLabel(_("Wallet derivation path") + ':'), grid_row, 0)
            grid_maybe.addWidget(der_e, grid_row, 1)
            grid_row += 1
        if grid_maybe:
            self.addLayout(grid_maybe)
        self.addStretch(1)
        self.seed_warning = WWLabel('')
        if msg:
            self.seed_warning.setText(seed_warning_msg(seed, derivation))
        self.addWidget(self.seed_warning)

    def get_seed(self):
        text = self.seed_e.text()
        return ' '.join(text.split())

    def on_edit(self):
        from electroncash.bitcoin import seed_type
        s = self.get_seed()
        b = self.is_seed(s)
        if not self.is_bip39:
            t = seed_type(s)
            label = _('Seed Type') + ': ' + t if t else ''
        else:
            from electroncash.keystore import bip39_is_checksum_valid
            is_checksum, is_wordlist = bip39_is_checksum_valid(s)
            status = ('checksum: ' + ('ok' if is_checksum else 'failed')) if is_wordlist else 'unknown wordlist'
            label = 'BIP39' + ' (%s)'%status
        self.seed_type_label.setText(label)
        self.parent.next_button.setEnabled(b)


class KeysLayout(QVBoxLayout):
    def __init__(self, parent=None, title=None, is_valid=None, allow_multi=False):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.is_valid = is_valid
        self.text_e = ScanQRTextEdit(allow_multi=allow_multi)
        self.text_e.textChanged.connect(self.on_edit)
        self.addWidget(WWLabel(title))
        self.addWidget(self.text_e)

    def get_text(self):
        return self.text_e.text()

    def on_edit(self):
        b = self.is_valid(self.get_text())
        self.parent.next_button.setEnabled(b)


class SeedDialog(WindowModalDialog):

    def __init__(self, parent, seed, passphrase, derivation=None):
        WindowModalDialog.__init__(self, parent, ('Electron Cash - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(title=title, seed=seed, msg=True, passphrase=passphrase, editable=False, derivation=derivation)
        vbox.addLayout(slayout)
        vbox.addLayout(Buttons(CloseButton(self)))
