import bb.cascades 1.4

/*
 * ImportSheet - "New profile", or a new .conf for one (docs/APP.md, section 5): one sheet for every
 * source - a file (picked, or opened "in Tunnel" from another app), a QR code, pasted text.
 *
 *   - an AmneziaVPN key (vpn://...) - its text, a .vpn file, AmneziaVPN's QR codes - is made the .conf
 *     of its connection here (importer.fromAmneziaKey), and the sheet goes on with that; the name is
 *     the key's own. A key that holds no connection says why;
 *   - the text of a file or a QR code is folded ("Show and edit the text"): the private key does not
 *     flash on screen for nothing. Pasted text opens straight in the editor;
 *   - the daemon checks it (profile.import / profile.update conf=): a mistake comes back with its line
 *     under the text, and the sheet stays open to fix it in place;
 *   - done: the sheet closes and main.qml says so (imported). The text is wiped from the fields - the
 *     app keeps no copy of a key; the file it came from stays where it was.
 *
 * main.qml calls prepare() and open(). The fields' text is mirrored from onTextChanging: a text field's
 * `text` is not live on BB10 (KB 1.26).
 */
Sheet {
    id: sheet

    // "new" | "replace" - then `profileId` is whose .conf.
    property string mode: "new"
    property string profileId: ""
    // "file" | "qr" | "paste"
    property string source: "paste"
    property string fileName: ""
    property string nameText: ""
    property string confText: ""
    property bool showText: false
    // The text came as an AmneziaVPN key; confText is its connection's .conf now.
    property bool fromKey: false
    // The request being answered, 0 when none.
    property int request: 0
    property string error: ""

    // Named apart from the sheet's own properties: a handler sees both.
    signal imported(string doneId, string doneMode, string doneNote)
    // The text is a Tailscale auth key: its own sheet takes it (main.qml).
    signal tailscaleKey(string key)

    // A new profile from a Tailscale key: this sheet closes, the key goes on. true when it did.
    function passKey(text) {
        if (sheet.mode !== "new" || importer.kind(text) !== "tailscale-key") {
            return false;
        }
        var key = text.trim();
        sheet.clear();
        sheet.close();
        sheet.tailscaleKey(key);
        return true;
    }

    function prepare(mode, profileId, source, text, fileName, name) {
        sheet.mode = mode;
        sheet.profileId = profileId;
        sheet.source = source;
        sheet.fileName = fileName;
        sheet.confText = text;
        confArea.text = text;
        sheet.nameText = name;
        nameField.text = name;
        sheet.showText = source === "paste";
        sheet.fromKey = false;
        sheet.error = "";
        sheet.request = 0;
        if (importer.kind(text) === "amnezia-key") {
            // The key's name over the file's: AmneziaVPN names every file it saves alike.
            sheet.takeKey(text, true);
        }
    }

    function clear() {
        confArea.text = "";
        sheet.confText = "";
        nameField.text = "";
        sheet.nameText = "";
        sheet.fromKey = false;
        sheet.error = "";
        sheet.request = 0;
    }

    // An AmneziaVPN key: its connection's .conf in its place. false when it holds none - then the
    // error says why.
    function takeKey(text, keyName) {
        var r = importer.fromAmneziaKey(text);
        if (! r.ok) {
            sheet.error = sheet.keyError(r.error, r.detail);
            return false;
        }
        confArea.text = r.conf;
        sheet.confText = r.conf;
        sheet.fromKey = true;
        sheet.showText = false;
        if (sheet.mode === "new" && r.name !== "" && (keyName || sheet.nameText.trim() === "")) {
            nameField.text = r.name;
            sheet.nameText = r.name;
        }
        sheet.error = "";
        return true;
    }

    function keyError(code, detail) {
        if (code === "subscription") {
            return qsTr("This is an AmneziaVPN subscription key (AmneziaFree or Premium): its connection comes from Amnezia's servers each time, and Tunnel cannot fetch it.");
        }
        if (code === "full-access") {
            return qsTr("This key gives full access to a server, not a connection. In AmneziaVPN, share a connection for AmneziaWG or WireGuard instead.");
        }
        if (code === "other-protocols") {
            return qsTr("Tunnel speaks WireGuard and AmneziaWG, and this key holds only: %1.").arg(detail);
        }
        if (code === "no-connection") {
            return qsTr("This key holds no WireGuard or AmneziaWG connection. In AmneziaVPN, share a connection for AmneziaWG or WireGuard.");
        }
        return qsTr("This vpn:// key cannot be read: it is damaged or cut short.");
    }

    function accept() {
        if (sheet.passKey(sheet.confText)) {
            return;
        }
        if (importer.kind(sheet.confText) === "amnezia-key" && ! sheet.takeKey(sheet.confText, false)) {
            return;
        }
        var kind = importer.kind(sheet.confText);
        if (kind !== "conf") {
            sheet.error = qsTr("This is not a WireGuard or AmneziaWG configuration: it has no [Interface] section.");
            sheet.showText = true;
            return;
        }
        if (sheet.mode === "new" && sheet.nameText.trim() === "") {
            sheet.error = qsTr("Give the profile a name.");
            return;
        }
        sheet.error = "";
        sheet.request = sheet.mode === "replace"
                ? profiles.replaceConf(sheet.profileId, sheet.confText)
                : profiles.importProfile(sheet.nameText.trim(), sheet.confText);
        if (sheet.request === 0) {
            sheet.error = daemon.connected
                    ? qsTr("This configuration is too big.")
                    : qsTr("The tunnel service is not running.");
        }
    }

    function onImportDone(request, ok, id, error, line, note) {
        if (request !== sheet.request || request === 0) {
            return;
        }
        sheet.request = 0;
        if (! ok) {
            sheet.error = line > 0 ? qsTr("Line %1: %2").arg(line).arg(error) : error;
            sheet.showText = true;
            return;
        }
        var mode = sheet.mode;
        var who = id !== "" ? id : sheet.profileId;
        sheet.clear();
        sheet.close();
        sheet.imported(who, mode, note);
    }

    onCreationCompleted: {
        profiles.importDone.connect(sheet.onImportDone);
    }

    Page {
        titleBar: TitleBar {
            title: (sheet.mode === "replace"
                    ? qsTr("New configuration")
                    : qsTr("New profile")) + Retranslate.onLocaleOrLanguageChanged

            dismissAction: ActionItem {
                title: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
                onTriggered: {
                    sheet.clear();
                    sheet.close();
                }
            }

            acceptAction: ActionItem {
                title: (sheet.mode === "replace"
                        ? qsTr("Replace")
                        : qsTr("Add")) + Retranslate.onLocaleOrLanguageChanged
                enabled: sheet.request === 0 && daemon.connected
                onTriggered: {
                    sheet.accept();
                }
            }
        }

        ScrollView {
            scrollRole: ScrollRole.Main

            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                topPadding: ui.du(dimens.pad)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)
                bottomPadding: ui.du(15)

                // ---- The name (a new profile only) --------------------------------------------------------
                Label {
                    visible: sheet.mode === "new"
                    text: qsTr("Name") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.base: SystemDefaults.TextStyles.SubtitleText
                    bottomMargin: 0
                }

                TextField {
                    id: nameField
                    visible: sheet.mode === "new"
                    hintText: qsTr("Home, Work...") + Retranslate.onLocaleOrLanguageChanged
                    input.flags: TextInputFlag.SpellCheckOff | TextInputFlag.AutoCorrectionOff
                    onTextChanging: {
                        sheet.nameText = text;
                    }
                    onTextChanged: {
                        sheet.nameText = text;
                    }
                }

                // ---- Where it came from -----------------------------------------------------------------
                // A key that held no connection is not a configuration: its error below says it all.
                Label {
                    visible: (sheet.source !== "paste" || sheet.fromKey) && importer.kind(sheet.confText) !== "amnezia-key"
                    topMargin: ui.du(dimens.gap)
                    text: (sheet.fromKey
                            ? (sheet.source === "file"
                                    ? qsTr("An AmneziaVPN key from the file %1: a configuration of %2 lines").arg(sheet.fileName).arg(importer.lineCount(sheet.confText))
                                    : qsTr("An AmneziaVPN key: a configuration of %1 lines").arg(importer.lineCount(sheet.confText)))
                            : (sheet.source === "file"
                                    ? qsTr("Configuration from the file %1, %2 lines").arg(sheet.fileName).arg(importer.lineCount(sheet.confText))
                                    : qsTr("Configuration from a QR code, %1 lines").arg(importer.lineCount(sheet.confText)))) + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    multiline: true
                }

                Button {
                    visible: ! sheet.showText
                    horizontalAlignment: HorizontalAlignment.Fill
                    text: qsTr("Show and edit the text") + Retranslate.onLocaleOrLanguageChanged
                    imageSource: "asset:///images/ic_edit.png"
                    onClicked: {
                        sheet.showText = true;
                    }
                }

                Button {
                    visible: sheet.source === "paste"
                    topMargin: ui.du(dimens.gap)
                    horizontalAlignment: HorizontalAlignment.Fill
                    text: qsTr("Paste from the clipboard") + Retranslate.onLocaleOrLanguageChanged
                    onClicked: {
                        var text = importer.clipboardText();
                        if (sheet.passKey(text)) {
                            return;
                        }
                        confArea.text = text;
                        sheet.confText = text;
                        if (importer.kind(text) === "amnezia-key") {
                            sheet.takeKey(text, false);
                        }
                    }
                }

                // ---- The .conf ----------------------------------------------------------------------------
                TextArea {
                    id: confArea
                    visible: sheet.showText
                    topMargin: ui.du(dimens.gap)
                    horizontalAlignment: HorizontalAlignment.Fill
                    preferredHeight: ui.du(60)
                    hintText: qsTr("Paste the .conf here") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.fontFamily: "monospace"
                    textStyle.base: SystemDefaults.TextStyles.SmallText
                    input.flags: TextInputFlag.SpellCheckOff | TextInputFlag.AutoCorrectionOff | TextInputFlag.AutoCapitalizationOff | TextInputFlag.PredictionOff | TextInputFlag.AutoPeriodOff | TextInputFlag.WordSubstitutionOff
                    onTextChanging: {
                        sheet.confText = text;
                    }
                    onTextChanged: {
                        sheet.confText = text;
                    }
                }

                // ---- The daemon's answer ------------------------------------------------------------------
                Label {
                    visible: sheet.error !== ""
                    topMargin: ui.du(dimens.gap)
                    text: sheet.error
                    textStyle.color: Color.Red
                    multiline: true
                }

                ActivityIndicator {
                    visible: sheet.request !== 0
                    running: visible
                    topMargin: ui.du(dimens.gap)
                    horizontalAlignment: HorizontalAlignment.Center
                    preferredWidth: ui.du(8)
                    preferredHeight: ui.du(8)
                }
            }
        }
    }
}
