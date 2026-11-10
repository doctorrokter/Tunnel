/*
 * SettingsPage - the settings hub, pushed from the app menu (Menu.definition): one row per group, each
 * pushing its own page onto the same stack (main.qml wires the signals below). The rows carry no
 * settings of their own - they only navigate - so a new group is a new page plus a row here.
 *
 * The shape of BBTelega's, BBHealth's and Syno's hubs (docs/APP.md, section 6), with bb-shared's
 * SettingsItem rows.
 */
import bb.cascades 1.4
import "../shared"

Page {
    id: settingsPage

    // main.qml keeps the app menu off while the settings are open (one hub at a time).
    objectName: "settings"

    signal connectionSettingsRequested()
    signal notificationSettingsRequested()
    signal languageSettingsRequested()
    signal diagnosticsRequested()

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
    actionBarVisibility: ChromeVisibility.Overlay

    titleBar: TitleBar {
        title: qsTr("Settings") + Retranslate.onLocaleOrLanguageChanged
    }

    // The always-on profiles' names, "" for none: one of each kind can be always on.
    function alwaysOnName() {
        var ids = [
            profiles.alwaysOn,
            profiles.alwaysOnTailscale
        ];
        var names = [];
        for (var i = 0; i < ids.length; ++ i) {
            var profile = ids[i] !== "" ? profiles.find(ids[i]) : null;
            if (profile !== null) {
                names.push(profile.name);
            }
        }
        return names.join(", ");
    }

    ScrollView {
        scrollRole: ScrollRole.Main

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            bottomPadding: ui.du(15)

            SettingsItem {
                title: qsTr("Connection") + Retranslate.onLocaleOrLanguageChanged
                // Which profiles are always on.
                description: (settingsPage.alwaysOnName() !== ""
                        ? qsTr("Always on: %1").arg(settingsPage.alwaysOnName())
                        : qsTr("Always on: none")) + Retranslate.onLocaleOrLanguageChanged
                imageSource: "asset:///images/ic_lock.png"
                onTapped: settingsPage.connectionSettingsRequested()
            }

            SettingsItem {
                title: qsTr("Notifications") + Retranslate.onLocaleOrLanguageChanged
                description: qsTr("Connection lost, the tunnel service") + Retranslate.onLocaleOrLanguageChanged
                imageSource: "asset:///images/ic_notification.png"
                onTapped: settingsPage.notificationSettingsRequested()
            }

            SettingsItem {
                title: qsTr("Language") + Retranslate.onLocaleOrLanguageChanged
                // The current choice: "System" translated, a language in its own name from the L10n
                // registry - no per-language branch here (BBHealth). Re-evaluates on the setting AND
                // on a device language change.
                description: (settings.language === "system"
                        ? qsTr("System")
                        : settings.languageName(settings.language)) + Retranslate.onLocaleOrLanguageChanged
                imageSource: "asset:///images/ic_sb_network.png"
                onTapped: settingsPage.languageSettingsRequested()
            }

            SettingsItem {
                title: qsTr("Diagnostics") + Retranslate.onLocaleOrLanguageChanged
                description: qsTr("The tunnel service's log, versions") + Retranslate.onLocaleOrLanguageChanged
                imageSource: "asset:///images/ic_diagnostics.png"
                onTapped: settingsPage.diagnosticsRequested()
            }
        }
    }
}
