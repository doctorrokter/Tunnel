import bb.cascades 1.4
import "../shared"

/*
 * NotificationSettingsPage - Settings > Notifications (docs/APP.md, section 11): what the background
 * service says in the Hub. The switches are the app's settings (client/TunnelSettings.hpp); the
 * service reads them at the moment of saying - and sees a change at once.
 */
Page {
    titleBar: TitleBar {
        title: qsTr("Notifications") + Retranslate.onLocaleOrLanguageChanged
    }

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
    actionBarVisibility: ChromeVisibility.Overlay

    ScrollView {
        scrollRole: ScrollRole.Main

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            bottomPadding: ui.du(15)

            ToggleableListItem {
                title: qsTr("Connection lost") + Retranslate.onLocaleOrLanguageChanged
                subtitle: qsTr("A tunnel reconnects, or does not connect, for longer than 30 seconds. A switch of networks is shorter and is not reported.") + Retranslate.onLocaleOrLanguageChanged
                checked: settings.notifyLost
                onToggled: {
                    settings.notifyLost = checked;
                }
            }

            ToggleableListItem {
                title: qsTr("The tunnel service does not answer") + Retranslate.onLocaleOrLanguageChanged
                subtitle: qsTr("It stopped and did not come back within a minute - no tunnel works until it does.") + Retranslate.onLocaleOrLanguageChanged
                checked: settings.notifyDaemon
                onToggled: {
                    settings.notifyDaemon = checked;
                }
            }

            ToggleableListItem {
                title: qsTr("While connected") + Retranslate.onLocaleOrLanguageChanged
                subtitle: qsTr("A quiet entry in the Hub while a tunnel is up: BB10 shows no VPN mark for it.") + Retranslate.onLocaleOrLanguageChanged
                checked: settings.notifyConnected
                onToggled: {
                    settings.notifyConnected = checked;
                }
            }

            Label {
                topMargin: ui.du(dimens.gap)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)
                text: qsTr("They come from Tunnel's background service, also while the app is closed.") + Retranslate.onLocaleOrLanguageChanged
                textStyle.base: SystemDefaults.TextStyles.SubtitleText
                textStyle.color: ui.palette.secondaryTextOnPlain
                multiline: true
            }
        }
    }
}
