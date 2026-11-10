import bb.cascades 1.4

/*
 * TailscaleSheet - a Tailscale profile, or logging in again (docs/TAILSCALE.md, sections 3, 10 and 11b).
 * Two ways in, the user's choice:
 *
 *   - by a link: no key - at its start the tunnel gets a login link from Tailscale; the profile page
 *     shows it with its QR code, it is opened on a computer or another phone and logged in at with the
 *     user's account, and the phone connects by itself (profile.import type=tailscale login=link,
 *     profile.update login=link). main.qml starts the tunnel and opens its page then;
 *   - with an auth key made in the Tailscale admin console on a computer (Settings, Keys, Generate auth
 *     key) - pasted, typed, or read from a QR code (main.qml's scanner: qrRequested closes the sheet, the
 *     key brings it back). The key is wiped from the field once it is taken: the daemon sends it once
 *     and keeps none.
 *
 *   - new: a name too; the daemon makes the node's keys. The phone's name in the tailnet is its model;
 *   - relogin: for a login that expired or was refused; main.qml reconnects the tunnel then.
 *
 * The fields' text is mirrored from onTextChanging: a text field's `text` is not live on BB10 (KB 1.26).
 */
Sheet {
    id: sheet

    // "new" | "relogin" - then `profileId` is whose.
    property string mode: "new"
    property string profileId: ""
    // "link" | "key": how it logs in.
    property string how: "link"
    property string nameText: ""
    property string keyText: ""
    // The request being answered, 0 when none.
    property int request: 0
    property string error: ""

    // Named apart from the sheet's own properties: a handler sees both.
    signal done(string doneId, string doneMode, string doneHow)
    // The scanner, please: the sheet closes meanwhile, and comes back with what it read.
    signal qrRequested()

    // A key given (scanned, or opened "in Tunnel"): the key's way; none - as the user chose last.
    function prepare(mode, profileId, key) {
        sheet.mode = mode;
        sheet.profileId = profileId;
        sheet.error = "";
        sheet.request = 0;
        if (mode === "new" && sheet.nameText === "") {
            nameField.text = "Tailscale";
            sheet.nameText = "Tailscale";
        }
        keyField.text = key;
        sheet.keyText = key;
        if (key !== "") {
            sheet.choose("key");
        }
    }

    function choose(how) {
        sheet.how = how;
        howControl.selectedIndex = how === "key" ? 1 : 0;
        sheet.error = "";
    }

    function clear() {
        keyField.text = "";
        sheet.keyText = "";
        nameField.text = "";
        sheet.nameText = "";
        sheet.error = "";
        sheet.request = 0;
    }

    function accept() {
        var key = sheet.keyText.trim();
        if (sheet.mode === "new" && sheet.nameText.trim() === "") {
            sheet.error = qsTr("Give the profile a name.");
            return;
        }
        if (sheet.how === "key" && importer.kind(key) !== "tailscale-key") {
            sheet.error = qsTr("This is not a Tailscale auth key: it starts with \"tskey-\" and has no spaces.");
            return;
        }
        sheet.error = "";
        if (sheet.how === "link") {
            sheet.request = sheet.mode === "relogin"
                    ? profiles.reloginLink(sheet.profileId)
                    : profiles.importTailscaleLink(sheet.nameText.trim(), importer.deviceHostname());
        } else {
            sheet.request = sheet.mode === "relogin"
                    ? profiles.relogin(sheet.profileId, key)
                    : profiles.importTailscale(sheet.nameText.trim(), key, importer.deviceHostname());
        }
        if (sheet.request === 0) {
            sheet.error = qsTr("The tunnel service is not running.");
        }
    }

    function onImportDone(request, ok, id, error, line, note) {
        if (request !== sheet.request || request === 0) {
            return;
        }
        sheet.request = 0;
        if (! ok) {
            sheet.error = error;
            return;
        }
        var mode = sheet.mode;
        var how = sheet.how;
        var who = id !== "" ? id : sheet.profileId;
        sheet.clear();
        sheet.close();
        sheet.done(who, mode, how);
    }

    onCreationCompleted: {
        profiles.importDone.connect(sheet.onImportDone);
    }

    Page {
        titleBar: TitleBar {
            // The brand is no word to translate.
            title: sheet.mode === "relogin" ? qsTr("Log in again") + Retranslate.onLocaleOrLanguageChanged : "Tailscale"

            dismissAction: ActionItem {
                title: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
                onTriggered: {
                    sheet.clear();
                    sheet.close();
                }
            }

            acceptAction: ActionItem {
                title: (sheet.mode === "relogin"
                        ? qsTr("Log in")
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
                    hintText: "Tailscale"
                    input.flags: TextInputFlag.SpellCheckOff | TextInputFlag.AutoCorrectionOff
                    onTextChanging: {
                        sheet.nameText = text;
                    }
                    onTextChanged: {
                        sheet.nameText = text;
                    }
                }

                // ---- How it logs in -----------------------------------------------------------------------
                SegmentedControl {
                    id: howControl
                    topMargin: ui.du(dimens.gap)
                    horizontalAlignment: HorizontalAlignment.Fill

                    Option {
                        text: qsTr("By a link") + Retranslate.onLocaleOrLanguageChanged
                        value: "link"
                        selected: true
                    }

                    Option {
                        text: qsTr("Auth key") + Retranslate.onLocaleOrLanguageChanged
                        value: "key"
                    }

                    onSelectedIndexChanged: {
                        sheet.how = selectedIndex === 1 ? "key" : "link";
                        sheet.error = "";
                    }
                }

                // ---- By a link ----------------------------------------------------------------------------
                Label {
                    visible: sheet.how === "link"
                    topMargin: ui.du(dimens.gap)
                    text: qsTr("No key needed. The phone gets a login link from Tailscale and shows it with its QR code. Open it on a computer or another phone and log in with your Tailscale account - Google, Microsoft, GitHub, Apple. The phone connects by itself once you are in.") + Retranslate.onLocaleOrLanguageChanged
                    multiline: true
                }

                Label {
                    visible: sheet.how === "link"
                    topMargin: ui.du(dimens.gap)
                    text: qsTr("A device logged in with an account has to log in again when its login expires - in 180 days, unless the expiry is turned off for it in the Tailscale admin console. A tagged auth key never expires.") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    multiline: true
                }

                // ---- With an auth key ---------------------------------------------------------------------
                Label {
                    visible: sheet.how === "key"
                    topMargin: ui.du(dimens.gap)
                    text: qsTr("Auth key") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.base: SystemDefaults.TextStyles.SubtitleText
                    bottomMargin: 0
                }

                TextField {
                    id: keyField
                    visible: sheet.how === "key"
                    hintText: "tskey-auth-..."
                    textStyle.fontFamily: "monospace"
                    input.flags: TextInputFlag.SpellCheckOff | TextInputFlag.AutoCorrectionOff | TextInputFlag.AutoCapitalizationOff | TextInputFlag.PredictionOff | TextInputFlag.AutoPeriodOff | TextInputFlag.WordSubstitutionOff
                    onTextChanging: {
                        sheet.keyText = text;
                    }
                    onTextChanged: {
                        sheet.keyText = text;
                    }
                }

                Container {
                    visible: sheet.how === "key"
                    topMargin: ui.du(dimens.gap)
                    horizontalAlignment: HorizontalAlignment.Fill
                    layout: StackLayout {
                        orientation: LayoutOrientation.LeftToRight
                    }

                    Button {
                        text: qsTr("Paste") + Retranslate.onLocaleOrLanguageChanged
                        layoutProperties: StackLayoutProperties {
                            spaceQuota: 1
                        }
                        onClicked: {
                            var text = importer.clipboardText().trim();
                            keyField.text = text;
                            sheet.keyText = text;
                        }
                    }

                    Button {
                        text: qsTr("Scan a QR code") + Retranslate.onLocaleOrLanguageChanged
                        layoutProperties: StackLayoutProperties {
                            spaceQuota: 1
                        }
                        onClicked: {
                            sheet.close();
                            sheet.qrRequested();
                        }
                    }
                }

                Label {
                    visible: sheet.how === "key"
                    topMargin: ui.du(dimens.gap)
                    text: qsTr("Make the key in the Tailscale admin console on a computer: Settings, Keys, Generate auth key. Not ephemeral, pre-approved, and with a tag (for example tag:phone) - then the device stays in the tailnet and its login never expires. The key is sent once and not kept.") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    multiline: true
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
