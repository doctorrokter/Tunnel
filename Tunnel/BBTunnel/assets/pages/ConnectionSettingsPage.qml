import bb.cascades 1.4
import bb.shared 1.0
import "../components"

/*
 * ConnectionSettingsPage - Settings > Connection (docs/APP.md, section 6): the always-on profiles, one
 * WireGuard or AmneziaWG profile and one Tailscale profile, as the app lets them run together. The
 * daemon keeps them (settings.set always_on=) and brings them up itself when it starts - the phone's
 * boot - and across network changes. The kill switch is not here: the daemon of v1 does not enforce
 * it (DAEMON section 8).
 *
 * A kind with no profiles has no choice to offer, so its radios are not made.
 */
Page {
    id: page

    function hasProfiles(tailscale) {
        var all = profiles.all;
        for (var i = 0; i < all.length; ++ i) {
            if (all[i].tailscale === tailscale) {
                return true;
            }
        }
        return false;
    }

    titleBar: TitleBar {
        title: qsTr("Connection") + Retranslate.onLocaleOrLanguageChanged
    }

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
    actionBarVisibility: ChromeVisibility.Overlay

    ScrollView {
        scrollRole: ScrollRole.Main

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            bottomPadding: ui.du(15)

            Header {
                title: qsTr("Always on") + Retranslate.onLocaleOrLanguageChanged
            }

            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                topPadding: ui.du(dimens.gap)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)
                bottomPadding: ui.du(dimens.gap)

                Label {
                    text: qsTr("The profiles chosen here come up when the tunnel service starts - when the phone boots - and stay up across network changes.") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    multiline: true
                }
            }

            Loader {
                active: page.hasProfiles(false)

                AlwaysOnRadios {
                    title: qsTr("WireGuard and AmneziaWG") + Retranslate.onLocaleOrLanguageChanged
                    tailscale: false
                }
            }

            Loader {
                active: page.hasProfiles(true)

                AlwaysOnRadios {
                    title: "Tailscale"
                    tailscale: true
                }
            }
        }
    }
}
