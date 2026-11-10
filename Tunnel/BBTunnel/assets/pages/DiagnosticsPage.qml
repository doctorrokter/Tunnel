import bb.cascades 1.4
import bb.system 1.2
import "../shared"

/*
 * DiagnosticsPage - Settings > Diagnostics (docs/APP.md, section 6): which daemon runs and which one
 * the app ships, the daemon's log (log.tail), sharing the logs - the boot loop's, the daemon's and
 * the service's in one file (app.logForSharing; the share itself only from QML, an unbound Invocation), a restart of
 * the tunnel service - not while an older one waits for the reboot that starts the new one - the
 * daemon's detailed log (log.debug, off by itself after 30 minutes), and in a development build the
 * demo switch.
 */
Page {
    id: page

    property int logRequest: 0
    property string logText: ""
    // An older daemon runs than the app ships: the new one starts after a reboot, and a restart now
    // would leave no service until then (docs/APP.md, section 9).
    property bool updatePending: daemon.connected && ! daemon.demo && daemon.daemonVersion !== app.bundledDaemonVersion
    // Set while a share is armed, so onArmed triggers exactly once (BBTelega's way).
    property bool sharePending: false
    // The daemon's debug lines (log.debug): on for 30 minutes at most, then off by itself.
    property bool debugLog: false
    // "hh:mm" it turns off at; "" - off, or on with no end (a daemon started with --debug).
    property string debugUntil: ""

    function requestLog() {
        page.logRequest = daemon.send("log.tail", { "lines": "200" });
    }

    function requestDebug() {
        daemon.send("log.debug", {});
    }

    function onReplied(id, cmd, reply, items) {
        if (id === page.logRequest && id !== 0) {
            page.logText = reply.text !== undefined ? reply.text : "";
        }
        if (cmd === "log.debug") {
            if (reply.errno === "0") {
                var left = parseInt(reply.left, 10);
                page.debugLog = reply.debug === "1";
                if (page.debugLog && left > 0) {
                    page.debugUntil = Qt.formatTime(new Date(new Date().getTime() + left * 1000), "hh:mm");
                } else {
                    page.debugUntil = "";
                }
            } else {
                debugItem.reset();
            }
        }
    }

    // A new connection may be another daemon (a restart, a reboot): its state is asked again.
    function onConnectedChanged() {
        if (daemon.connected) {
            page.requestDebug();
        }
    }

    function shareLog() {
        var uri = app.logForSharing();
        if (uri === "") {
            toast.body = qsTr("There is no log yet.");
            toast.show();
            return;
        }
        shareInvoke.query.uri = uri;
        page.sharePending = true;
        shareInvoke.query.updateQuery();
    }

    // main.qml, when the page goes.
    function cleanup() {
        daemon.replied.disconnect(page.onReplied);
        daemon.connectedChanged.disconnect(page.onConnectedChanged);
    }

    onCreationCompleted: {
        daemon.replied.connect(page.onReplied);
        daemon.connectedChanged.connect(page.onConnectedChanged);
        page.requestLog();
        page.requestDebug();
    }

    titleBar: TitleBar {
        title: qsTr("Diagnostics") + Retranslate.onLocaleOrLanguageChanged
    }

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
    actionBarVisibility: ChromeVisibility.Overlay

    actions: [
        ActionItem {
            title: qsTr("Refresh") + Retranslate.onLocaleOrLanguageChanged
            imageSource: "asset:///images/ic_refresh.png"
            ActionBar.placement: ActionBarPlacement.OnBar
            enabled: daemon.connected
            onTriggered: {
                page.requestLog();
                page.requestDebug();
            }
        },
        ActionItem {
            title: qsTr("Share the logs") + Retranslate.onLocaleOrLanguageChanged
            imageSource: "asset:///images/ic_share.png"
            ActionBar.placement: ActionBarPlacement.OnBar
            onTriggered: {
                page.shareLog();
            }
        }
    ]

    ScrollView {
        scrollRole: ScrollRole.Main

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            bottomPadding: ui.du(15)

            // ---- Versions ------------------------------------------------------------------------------
            Header {
                title: qsTr("Versions") + Retranslate.onLocaleOrLanguageChanged
            }

            PropListItem {
                name: qsTr("App") + Retranslate.onLocaleOrLanguageChanged
                value: Application.applicationVersion
            }

            PropListItem {
                name: qsTr("Tunnel service") + Retranslate.onLocaleOrLanguageChanged
                value: (daemon.connected
                        ? qsTr("%1, protocol %2").arg(daemon.daemonVersion).arg(daemon.protoVersion)
                        : qsTr("not running")) + Retranslate.onLocaleOrLanguageChanged
            }

            PropListItem {
                name: qsTr("Tunnel service in this app") + Retranslate.onLocaleOrLanguageChanged
                value: app.bundledDaemonVersion
            }

            // ---- The log -------------------------------------------------------------------------------
            Header {
                title: qsTr("The tunnel service's log") + Retranslate.onLocaleOrLanguageChanged
            }

            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)

                // Read-only TextArea: text that can be selected and copied.
                TextArea {
                    editable: false
                    horizontalAlignment: HorizontalAlignment.Fill
                    text: page.logText !== ""
                            ? page.logText
                            : (daemon.connected ? "" : qsTr("The tunnel service is not running.") + Retranslate.onLocaleOrLanguageChanged)
                    textStyle.base: SystemDefaults.TextStyles.SmallText
                }
            }

            // ---- The service ---------------------------------------------------------------------------
            Header {
                title: qsTr("Tunnel service") + Retranslate.onLocaleOrLanguageChanged
            }

            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                topPadding: ui.du(dimens.gap)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)

                Label {
                    visible: page.updatePending
                    horizontalAlignment: HorizontalAlignment.Fill
                    bottomMargin: ui.du(dimens.gap)
                    multiline: true
                    text: qsTr("The new tunnel service starts when the phone restarts. Until then this one keeps working.") + Retranslate.onLocaleOrLanguageChanged
                }

                Button {
                    horizontalAlignment: HorizontalAlignment.Fill
                    text: qsTr("Restart the tunnel service") + Retranslate.onLocaleOrLanguageChanged
                    imageSource: "asset:///images/ic_reload.png"
                    enabled: daemon.connected && ! page.updatePending
                    onClicked: {
                        restartDialog.show();
                    }
                }
            }

            ToggleableListItem {
                id: debugItem
                visible: daemon.connected
                topMargin: ui.du(dimens.gap)
                title: qsTr("Detailed service log") + Retranslate.onLocaleOrLanguageChanged
                subtitle: (page.debugLog && page.debugUntil !== ""
                        ? qsTr("On until %1, then it turns itself off.").arg(page.debugUntil)
                        : qsTr("For finding faults. Turns itself off after 30 minutes; the service's log never takes more than 512 KB.")) + Retranslate.onLocaleOrLanguageChanged
                checked: page.debugLog
                onToggled: {
                    daemon.send("log.debug", { "on": checked ? "1" : "0" });
                }
            }

            // ---- Developer: the demo daemon ---------------------------------------------------------------
            ToggleableListItem {
                visible: devMode
                topMargin: ui.du(dimens.gap)
                title: qsTr("Demo mode") + Retranslate.onLocaleOrLanguageChanged
                subtitle: qsTr("Made-up profiles instead of the tunnel service. Takes effect when the app starts again.") + Retranslate.onLocaleOrLanguageChanged
                checked: settings.demoMode
                onToggled: {
                    settings.demoMode = checked;
                }
            }
        }
    }

    attachedObjects: [
        Invocation {
            id: shareInvoke
            query {
                mimeType: "text/plain"
                invokeActionId: "bb.action.SHARE"
            }
            onArmed: {
                if (page.sharePending) {
                    page.sharePending = false;
                    shareInvoke.trigger(shareInvoke.query.invokeActionId);
                }
            }
        },
        SystemDialog {
            id: restartDialog
            title: qsTr("Restart the tunnel service?") + Retranslate.onLocaleOrLanguageChanged
            body: qsTr("The tunnels go down for a few seconds; the always-on ones come back by themselves.") + Retranslate.onLocaleOrLanguageChanged
            confirmButton.label: qsTr("Restart") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection) {
                    daemon.send("daemon.restart", {});
                }
            }
        },
        SystemToast {
            id: toast
        }
    ]
}
