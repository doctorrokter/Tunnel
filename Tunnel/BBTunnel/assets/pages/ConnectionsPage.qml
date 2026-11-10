import bb.cascades 1.4
import bb.system 1.2
import bb.shared 1.0
import "../shared"
import "../StateText.js" as States

/*
 * ConnectionsPage - the main screen (docs/APP.md, section 3): the profiles, each with its state under
 * its name and a switch - on is tunnel.up, off is tunnel.down. The switch shows "the daemon holds the
 * tunnel" (connecting, up, reconnecting, error), not "a handshake went through", so it does not
 * twitch at every reconnect. A tap opens the profile, a long press offers connect / disconnect,
 * rename, always-on and delete.
 *
 * Instead of the list: the daemon not running (retried by itself, and at once on "Retry"), the first
 * load, no profiles yet (three ways to add one). All of it in one ScrollView, as on every page: on a
 * small screen they do not fit.
 *
 * The list is a bb-shared Repeater in a ScrollView, not a ListView: the profiles are a handful, and a
 * recycled ListView row would show another row's switch.
 */
Page {
    id: page

    // The profile whose long-press menu asked for a rename or a delete.
    property string menuId: ""

    signal openProfile(string id)
    signal addRequested()
    signal addFrom(string source)
    // The setup guide, please (the service is not running).
    signal setupRequested()

    titleBar: TitleBar {
        title: "Tunnel"
    }

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
    actionBarVisibility: ChromeVisibility.Overlay

    // A command the daemon refused (four tunnels already): every switch back to what its tunnel
    // really is. Called by main.qml - a row cannot hold a connection of its own (the Repeater rebuilds
    // rows, and Cascades has no onDestruction to let go of it).
    function resetSwitches() {
        for (var i = 0; i < rows.count(); i ++) {
            var row = rows.at(i);
            if (row.reset !== undefined) {
                row.reset();
            }
        }
    }

    function askRename(profile) {
        page.menuId = profile.id;
        renamePrompt.inputField.defaultText = profile.name;
        renamePrompt.show();
    }

    function askDelete(profile) {
        page.menuId = profile.id;
        deleteDialog.body = qsTr("Delete \"%1\"? Its keys go with it; a tunnel that is up is taken down first.").arg(profile.name);
        deleteDialog.show();
    }

    actions: [
        ActionItem {
            title: qsTr("Add") + Retranslate.onLocaleOrLanguageChanged
            imageSource: "asset:///images/ic_add.png"
            ActionBar.placement: ActionBarPlacement.Signature
            enabled: daemon.connected
            onTriggered: {
                page.addRequested();
            }
        }
    ]

    ScrollView {
        horizontalAlignment: HorizontalAlignment.Fill
        verticalAlignment: VerticalAlignment.Fill
        scrollRole: ScrollRole.Main

        attachedObjects: [
            LayoutUpdateHandler {
                id: scrollFrame
            }
        ]

        // At least as tall as the screen, so that a short state stands in its middle; a taller one (a
        // Q10) makes the page scroll.
        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            minHeight: scrollFrame.layoutFrame.height

            layout: DockLayout {
            }

            // ---- The daemon does not answer --------------------------------------------------------
            Container {
                visible: ! daemon.connected
                horizontalAlignment: HorizontalAlignment.Fill
                verticalAlignment: VerticalAlignment.Center
                topPadding: ui.du(dimens.pad)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)
                bottomPadding: ui.du(15)

                Label {
                    horizontalAlignment: HorizontalAlignment.Center
                    text: qsTr("The tunnel service is not running") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.base: SystemDefaults.TextStyles.TitleText
                    multiline: true
                }

                Label {
                    horizontalAlignment: HorizontalAlignment.Center
                    text: qsTr("It runs as root and starts when the phone boots. More in Help.") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    textStyle.textAlign: TextAlign.Center
                    multiline: true
                }

                Label {
                    horizontalAlignment: HorizontalAlignment.Center
                    text: qsTr("Tunnel keeps trying to reach it.") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.base: SystemDefaults.TextStyles.SubtitleText
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    textStyle.textAlign: TextAlign.Center
                    multiline: true
                }

                // Not to wait out the next try (up to 30 s) - the service was just started.
                Button {
                    horizontalAlignment: HorizontalAlignment.Center
                    topMargin: ui.du(dimens.pad)
                    text: qsTr("Retry") + Retranslate.onLocaleOrLanguageChanged
                    onClicked: {
                        daemon.retryNow();
                    }
                }

                // What it takes to have it running: the setup guide.
                Button {
                    horizontalAlignment: HorizontalAlignment.Center
                    topMargin: ui.du(dimens.gap)
                    text: qsTr("How to start the service") + Retranslate.onLocaleOrLanguageChanged
                    appearance: ControlAppearance.Plain
                    onClicked: {
                        page.setupRequested();
                    }
                }
            }

            // ---- The first load -------------------------------------------------------------------
            ActivityIndicator {
                visible: daemon.connected && ! profiles.loaded
                running: visible
                horizontalAlignment: HorizontalAlignment.Center
                verticalAlignment: VerticalAlignment.Center
                preferredWidth: ui.du(10)
                preferredHeight: ui.du(10)
            }

            // ---- No profiles yet -------------------------------------------------------------------
            Container {
                visible: daemon.connected && profiles.loaded && profiles.count === 0
                horizontalAlignment: HorizontalAlignment.Fill
                verticalAlignment: VerticalAlignment.Center
                topPadding: ui.du(dimens.pad)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)
                bottomPadding: ui.du(15)

                Label {
                    horizontalAlignment: HorizontalAlignment.Center
                    text: qsTr("No profiles yet") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.base: SystemDefaults.TextStyles.TitleText
                }

                Label {
                    horizontalAlignment: HorizontalAlignment.Center
                    bottomMargin: ui.du(dimens.pad)
                    text: qsTr("Add a WireGuard or AmneziaWG profile - the .conf or the AmneziaVPN key your server or its admin gave you.") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    textStyle.textAlign: TextAlign.Center
                    multiline: true
                }

                Button {
                    horizontalAlignment: HorizontalAlignment.Fill
                    text: qsTr("From a file") + Retranslate.onLocaleOrLanguageChanged
                    imageSource: "asset:///images/ic_doctype_generic.png"
                    onClicked: {
                        page.addFrom("file");
                    }
                }

                Button {
                    horizontalAlignment: HorizontalAlignment.Fill
                    text: qsTr("Scan a QR code") + Retranslate.onLocaleOrLanguageChanged
                    imageSource: "asset:///images/ic_camera.png"
                    onClicked: {
                        page.addFrom("qr");
                    }
                }

                Button {
                    horizontalAlignment: HorizontalAlignment.Fill
                    text: qsTr("Paste text") + Retranslate.onLocaleOrLanguageChanged
                    imageSource: "asset:///images/ic_edit.png"
                    onClicked: {
                        page.addFrom("paste");
                    }
                }
            }

            // ---- The profiles ----------------------------------------------------------------------
            Container {
                id: rows
                visible: daemon.connected && profiles.count > 0
                horizontalAlignment: HorizontalAlignment.Fill
                verticalAlignment: VerticalAlignment.Top
                bottomPadding: ui.du(15)

                Repeater {
                    model: profiles.all

                    ToggleableListItem {
                        id: row

                        property variant profile: modelData

                        title: row.profile.name
                        subtitle: States.row(row.profile) + Retranslate.onLocaleOrLanguageChanged
                        subtitleColor: States.bad(row.profile)
                                ? Color.Red
                                : (row.profile.state === "up" ? ui.palette.primary : ui.palette.secondaryTextOnPlain)
                        checked: row.profile.active

                        onToggled: {
                            if (checked) {
                                profiles.up(row.profile.id);
                            } else {
                                profiles.down(row.profile.id);
                            }
                        }

                        onTapped: {
                            page.openProfile(row.profile.id);
                        }

                        contextActions: [
                            ActionSet {
                                title: row.profile.name

                                ActionItem {
                                    title: (row.profile.active
                                            ? qsTr("Disconnect")
                                            : qsTr("Connect")) + Retranslate.onLocaleOrLanguageChanged
                                    imageSource: row.profile.active
                                            ? "asset:///images/ic_stop.png"
                                            : "asset:///images/ic_play.png"
                                    onTriggered: {
                                        if (row.profile.active) {
                                            profiles.down(row.profile.id);
                                        } else {
                                            profiles.up(row.profile.id);
                                        }
                                    }
                                }

                                ActionItem {
                                    title: qsTr("Rename") + Retranslate.onLocaleOrLanguageChanged
                                    imageSource: "asset:///images/ic_rename.png"
                                    onTriggered: {
                                        page.askRename(row.profile);
                                    }
                                }

                                ActionItem {
                                    title: (row.profile.alwaysOn
                                            ? qsTr("Not always on")
                                            : qsTr("Always on")) + Retranslate.onLocaleOrLanguageChanged
                                    imageSource: "asset:///images/ic_set_as_default.png"
                                    onTriggered: {
                                        profiles.setAlwaysOn(row.profile.id, ! row.profile.alwaysOn);
                                    }
                                }

                                DeleteActionItem {
                                    title: qsTr("Delete") + Retranslate.onLocaleOrLanguageChanged
                                    onTriggered: {
                                        page.askDelete(row.profile);
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    }

    attachedObjects: [
        SystemPrompt {
            id: renamePrompt
            title: qsTr("Rename") + Retranslate.onLocaleOrLanguageChanged
            confirmButton.label: qsTr("Save") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection) {
                    // The profile may have gone while the prompt was open.
                    var profile = profiles.find(page.menuId);
                    var name = renamePrompt.inputFieldTextEntry().trim();
                    if (profile !== null && name !== "" && name !== profile.name) {
                        profiles.rename(page.menuId, name);
                    }
                }
            }
        },
        SystemDialog {
            id: deleteDialog
            title: qsTr("Delete the profile") + Retranslate.onLocaleOrLanguageChanged
            confirmButton.label: qsTr("Delete") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection && profiles.find(page.menuId) !== null) {
                    profiles.remove(page.menuId);
                }
            }
        }
    ]
}
