import bb.cascades 1.4
import bb.platform 1.3
import "../shared"

/*
 * HelpSheet - the About / Help sheet (app menu -> Help), laid out like every app of ours: BBTelega's
 * is the reference, Syno's the one without a theme of its own. Native Header sections, `dimens`
 * spacing, default text sizes, the colours of the Cascades palette.
 *   - About: author (taps to GitHub), app, version, OS version.
 *   - Good to know: what Tunnel is, the tunnel service and root, adding a profile, the states,
 *     Russia, DNS, all traffic and parts of it (docs/APP.md, section 6).
 *   - Built with: the engine and OpenSSL.
 *   - Donate: bb-shared's "Buy me a coffee" card, which animates only while the sheet is open.
 */
Sheet {
    id: sheet

    onOpened: {
        coffee.animated = true;
    }

    onClosed: {
        coffee.animated = false;
    }

    Page {
        titleBar: TitleBar {
            title: qsTr("About") + Retranslate.onLocaleOrLanguageChanged

            dismissAction: ActionItem {
                title: qsTr("Close") + Retranslate.onLocaleOrLanguageChanged

                onTriggered: {
                    sheet.close();
                }
            }
        }

        actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
        actionBarVisibility: ChromeVisibility.Overlay

        ScrollView {
            scrollRole: ScrollRole.Main

            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                bottomPadding: ui.du(dimens.pad)

                // ---- About -----------------------------------------------------------------------
                Header {
                    title: qsTr("About") + Retranslate.onLocaleOrLanguageChanged
                }

                Container {
                    layout: StackLayout {
                        orientation: LayoutOrientation.LeftToRight
                    }
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)
                    topMargin: ui.du(dimens.gap)
                    bottomMargin: ui.du(dimens.gap)

                    Label {
                        text: qsTr("Author: ") + Retranslate.onLocaleOrLanguageChanged
                    }

                    Label {
                        text: "Mikhail Chachkouski"
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500

                        gestureHandlers: [
                            TapHandler {
                                onTapped: {
                                    githubInvoke.trigger(githubInvoke.query.invokeActionId);
                                }
                            }
                        ]
                    }
                }

                Container {
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)
                    bottomMargin: ui.du(dimens.gap)

                    Label {
                        text: qsTr("App: ") + Retranslate.onLocaleOrLanguageChanged + Application.applicationName
                    }

                    Label {
                        topMargin: 0
                        text: qsTr("Version: ") + Retranslate.onLocaleOrLanguageChanged + Application.applicationVersion
                        textStyle.color: ui.palette.secondaryTextOnPlain
                    }

                    Label {
                        topMargin: 0
                        text: qsTr("OS: ") + Retranslate.onLocaleOrLanguageChanged + platform.osVersion
                        textStyle.color: ui.palette.secondaryTextOnPlain
                    }
                }

                // ---- Good to know ------------------------------------------------------------------
                Header {
                    title: qsTr("Good to know") + Retranslate.onLocaleOrLanguageChanged
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("What Tunnel is") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("A VPN client for WireGuard and AmneziaWG servers, and for your Tailscale network. Its engine is its own, written for BlackBerry 10.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("The tunnel service") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("The tunnels are run by a service that works as root and starts when the phone boots - the app and its background service only talk to it. Without root it cannot run, and the app says the service is not running.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("Adding a profile") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("A profile is the .conf your server or its admin gives you, or an AmneziaVPN key (vpn://...): pick the file, scan its QR code, paste its text - or open it \"in Tunnel\" from a mail or the file manager. The file stays where it was, and it holds your private key: delete it once the profile is added.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("The states") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("Connecting - the first handshake is on its way. Reconnecting - the network changed or the server went quiet; the routes stay, so nothing goes past the tunnel meanwhile. The server does not answer - a wrong key, address or protocol, or a block.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("From Russia") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("Plain WireGuard is blocked there. Use an AmneziaWG profile: it disguises the traffic, and Tunnel speaks it.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("DNS") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("A profile with DNS= takes the phone's name lookups into the tunnel. Without it they go to the network's own server, past the tunnel.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: "Tailscale"
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("Your tailnet's devices - a NAS behind any router, a computer - by their 100.x addresses, from anywhere. Add a profile, choose Tailscale, and log in one of two ways. By a link: the phone shows a login link and its QR code - open it on a computer or another phone and log in with your Tailscale account; the login expires in 180 days unless the expiry is turned off for the device in the admin console. With an auth key: in the Tailscale admin console on a computer, Settings, Keys, Generate auth key; not ephemeral, pre-approved and with a tag (tag:phone, say) - the device then stays in the tailnet and its login never expires; paste the key or scan its QR code.") + Retranslate.onLocaleOrLanguageChanged
                    }

                    Label {
                        multiline: true
                        text: qsTr("The traffic goes directly when it can - in the same network (a NAS at home over Wi-Fi) and through the internet when the routers on both sides let it - otherwise through Tailscale's relays (DERP): slower, but they get through any network. Devices by name (MagicDNS) or by address; a tap on a device copies its address. From Russia, Tailscale's servers do not answer.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)
                    bottomMargin: ui.du(dimens.gap)

                    Label {
                        text: qsTr("All traffic, or a part of it") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("A profile with 0.0.0.0/0 takes all traffic, one with some networks only those. Several profiles can be on at once, but only one of them may take all traffic.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                // ---- Built with ------------------------------------------------------------------------
                Header {
                    title: qsTr("Built with") + Retranslate.onLocaleOrLanguageChanged
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("The tunnel engine") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("WireGuard and AmneziaWG, written anew in C on the ideas of wireguard-lwip (BSD-3-Clause) and OpenBSD's wg (ISC). WireGuard is a registered trademark of Jason A. Donenfeld.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    Label {
                        text: qsTr("The Tailscale client") + Retranslate.onLocaleOrLanguageChanged
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("Written anew in C on Tailscale's open protocol (BSD-3-Clause), with microlink (MIT) as a map of its bytes; jsmn (MIT) reads its JSON. Tailscale is a trademark of Tailscale Inc.; Tunnel is not made by them.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)
                    bottomMargin: ui.du(dimens.gap)

                    Label {
                        text: "OpenSSL 3.5.8 LTS"
                        textStyle.color: ui.palette.primary
                        textStyle.fontWeight: FontWeight.W500

                        gestureHandlers: [
                            TapHandler {
                                onTapped: {
                                    opensslInvoke.trigger(opensslInvoke.query.invokeActionId);
                                }
                            }
                        ]
                    }

                    Label {
                        topMargin: 0
                        multiline: true
                        text: qsTr("The cryptography: X25519, ChaCha20-Poly1305, BLAKE2s, Poly1305, and TLS for Tailscale. Apache License 2.0.") + Retranslate.onLocaleOrLanguageChanged
                    }
                }

                Divider {
                    bottomMargin: ui.du(dimens.gap)
                }

                // ---- Donate: bb-shared's card, the Boosty link and its copy button ----------------------
                Container {
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)

                    BuyMeACoffee {
                        id: coffee
                        animated: false
                        pad: dimens.pad
                        gap: dimens.gap
                    }
                }
            }
        }
    }

    attachedObjects: [
        PlatformInfo {
            id: platform
        },
        Invocation {
            id: githubInvoke
            query {
                uri: "https://github.com/doctorrokter"
                invokeActionId: "bb.action.OPEN"
                invokeTargetId: "sys.browser"
            }
        },
        Invocation {
            id: opensslInvoke
            query {
                uri: "https://www.openssl.org"
                invokeActionId: "bb.action.OPEN"
                invokeTargetId: "sys.browser"
            }
        }
    ]
}
