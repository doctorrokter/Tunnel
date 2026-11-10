import bb.cascades 1.4
import bb.shared 1.0
import "../components"

/*
 * OnboardingSheet - "How to start" (docs/APP.md, section 17): what has to be done before the app can
 * work, on four slides to swipe through - a horizontal ListView, one slide a flick, as Basket's - with
 * the dots, Skip and Next under them:
 *
 *   welcome  - what Tunnel is, and the two steps
 *   service  - the tunnel service runs as root and starts at boot; the off switch
 *   check    - reboot; whether the service answers, live (daemon.connected)
 *   profile  - the first profile: the sources' dialog of main.qml
 *
 * main.qml opens it at the first start (until settings.onboardingDone), from the app menu and from the
 * "service not running" screen; at the first start Done or Skip marks it seen. Created on open and
 * destroyed once closed (main.qml). The slides are made by the ListView and may be made anew when
 * far away: what they do is the ListView's functions - a slide reaches the sheet only through
 * ListItem.view.
 */
Sheet {
    id: sheet

    // Opened at the first start: Done or Skip marks the guide as seen.
    property bool firstRun: false
    // The slide on screen, and how many there are.
    property int current: 0
    property int count: 4

    // The first profile, please: main.qml offers the sources.
    signal addProfileRequested()

    function finish(addProfile) {
        if (sheet.firstRun) {
            settings.onboardingDone = true;
        }
        sheet.close();
        if (addProfile) {
            sheet.addProfileRequested();
        }
    }

    function go(index) {
        if (index < 0 || index >= sheet.count) {
            return;
        }
        sheet.current = index;
        slides.scrollToItem([ index ], ScrollAnimation.Smooth);
    }

    Page {
        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            verticalAlignment: VerticalAlignment.Fill
            layout: DockLayout {
            }

            // Tunnel's palette (APP.md, section 16): dark indigo to violet, under every slide.
            ImageView {
                horizontalAlignment: HorizontalAlignment.Fill
                verticalAlignment: VerticalAlignment.Fill
                imageSource: "asset:///images/onboarding/background.png"
                scalingMethod: ScalingMethod.Fill
            }

            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                verticalAlignment: VerticalAlignment.Fill
                layout: StackLayout {
                    orientation: LayoutOrientation.TopToBottom
                }

                ListView {
                    id: slides

                    // A slide's size: the ListView's own.
                    property real slideWidth: 0
                    property real slideHeight: 0

                    function addProfile() {
                        sheet.finish(true);
                    }

                    function itemType(data, indexPath) {
                        return data;
                    }

                    layoutProperties: StackLayoutProperties {
                        spaceQuota: 1
                    }
                    layout: StackListLayout {
                        orientation: LayoutOrientation.LeftToRight
                    }
                    flickMode: FlickMode.SingleItem
                    scrollIndicatorMode: ScrollIndicatorMode.None

                    dataModel: ArrayDataModel {
                        id: slideModel
                    }

                    listItemComponents: [
                        ListItemComponent {
                            type: "welcome"

                            OnboardingSlide {
                                id: welcomeSlide
                                preferredWidth: welcomeSlide.ListItem.view.slideWidth
                                preferredHeight: welcomeSlide.ListItem.view.slideHeight
                                glyph: "asset:///images/onboarding/wifi_locked.png"
                                title: "Tunnel"
                                text: qsTr("WireGuard, AmneziaWG and Tailscale on BlackBerry 10. It needs a phone with root v4. Before you start - two steps: restart the phone so that the tunnel service starts, and add your first profile.") + Retranslate.onLocaleOrLanguageChanged
                            }
                        },

                        ListItemComponent {
                            type: "service"

                            OnboardingSlide {
                                id: serviceSlide
                                preferredWidth: serviceSlide.ListItem.view.slideWidth
                                preferredHeight: serviceSlide.ListItem.view.slideHeight
                                glyph: "asset:///images/onboarding/service.png"
                                title: qsTr("The tunnel service") + Retranslate.onLocaleOrLanguageChanged
                                text: qsTr("The tunnels are run by a service that works as root and starts when the phone boots; the app only talks to it. Without root it cannot run. Should it ever get in the way: a file or a folder named tunnel-off in misc keeps it from starting.") + Retranslate.onLocaleOrLanguageChanged
                            }
                        },

                        ListItemComponent {
                            type: "check"

                            OnboardingSlide {
                                id: checkSlide
                                preferredWidth: checkSlide.ListItem.view.slideWidth
                                preferredHeight: checkSlide.ListItem.view.slideHeight
                                glyph: "asset:///images/onboarding/check.png"
                                title: qsTr("Reboot and check") + Retranslate.onLocaleOrLanguageChanged
                                text: qsTr("The app sets up the service's start at boot by itself. Restart the phone: the service comes up within 15 minutes after the boot, and here it says so. If it does not, its start log is misc/bbtunneld-boot.txt.") + Retranslate.onLocaleOrLanguageChanged

                                AdvancedContainer {
                                    horizontalAlignment: HorizontalAlignment.Fill
                                    cornerRadius: ui.du(1)
                                    color: daemon.connected ? Color.create("#4026c281") : Color.create("#26ffffff")
                                    topPadding: ui.du(1.5)
                                    bottomPadding: ui.du(1.5)
                                    leftPadding: ui.du(2)
                                    rightPadding: ui.du(2)

                                    Label {
                                        horizontalAlignment: HorizontalAlignment.Fill
                                        text: (daemon.connected
                                                ? qsTr("The service works: %1").arg(daemon.daemonVersion)
                                                : qsTr("The service is not running yet")) + Retranslate.onLocaleOrLanguageChanged
                                        multiline: true
                                        textStyle.color: Color.White
                                        textStyle.textAlign: TextAlign.Center
                                    }
                                }

                                // Not to wait out the client's next try (up to 30 s) after a reboot.
                                Button {
                                    visible: ! daemon.connected
                                    horizontalAlignment: HorizontalAlignment.Center
                                    topMargin: ui.du(1.5)
                                    text: qsTr("Check again") + Retranslate.onLocaleOrLanguageChanged
                                    onClicked: {
                                        daemon.retryNow();
                                    }
                                }
                            }
                        },

                        ListItemComponent {
                            type: "profile"

                            OnboardingSlide {
                                id: profileSlide
                                preferredWidth: profileSlide.ListItem.view.slideWidth
                                preferredHeight: profileSlide.ListItem.view.slideHeight
                                glyph: "asset:///images/onboarding/add.png"
                                title: qsTr("Your first profile") + Retranslate.onLocaleOrLanguageChanged
                                text: qsTr("Add a profile: a .conf file, a QR code, pasted text, an AmneziaVPN key, or a Tailscale login. Help is in the app menu, and so is this guide - How to start.") + Retranslate.onLocaleOrLanguageChanged

                                Button {
                                    horizontalAlignment: HorizontalAlignment.Center
                                    text: qsTr("Add a profile") + Retranslate.onLocaleOrLanguageChanged
                                    onClicked: {
                                        profileSlide.ListItem.view.addProfile();
                                    }
                                }
                            }
                        }
                    ]

                    attachedObjects: [
                        LayoutUpdateHandler {
                            onLayoutFrameChanged: {
                                slides.slideWidth = layoutFrame.width;
                                slides.slideHeight = layoutFrame.height;
                            }
                        },
                        // A flick ends on one slide: that one is current.
                        ListScrollStateHandler {
                            onScrollingChanged: {
                                if (! scrolling && firstVisibleItem.length > 0) {
                                    sheet.current = firstVisibleItem[0];
                                }
                            }
                        }
                    ]

                    onCreationCompleted: {
                        slideModel.append([ "welcome", "service", "check", "profile" ]);
                    }
                }

                // ---- The dots, Skip and Next -----------------------------------------------------------
                Container {
                    horizontalAlignment: HorizontalAlignment.Fill
                    topPadding: ui.du(1)
                    leftPadding: ui.du(dimens.pad)
                    rightPadding: ui.du(dimens.pad)
                    bottomPadding: ui.du(3)

                    // The current slide a longer pill.
                    Container {
                        horizontalAlignment: HorizontalAlignment.Center
                        layout: StackLayout {
                            orientation: LayoutOrientation.LeftToRight
                        }

                        Repeater {
                            model: [ 0, 1, 2, 3 ]

                            AdvancedContainer {
                                verticalAlignment: VerticalAlignment.Center
                                leftMargin: ui.du(0.6)
                                rightMargin: ui.du(0.6)
                                preferredWidth: sheet.current === modelData ? ui.du(3.5) : ui.du(1.4)
                                preferredHeight: ui.du(1.4)
                                cornerRadius: ui.du(0.7)
                                color: sheet.current === modelData ? Color.create("#2fd0ff") : Color.create("#59ffffff")
                            }
                        }
                    }

                    Container {
                        horizontalAlignment: HorizontalAlignment.Fill
                        topMargin: ui.du(2)
                        layout: DockLayout {
                        }

                        Container {
                            visible: sheet.current < sheet.count - 1
                            horizontalAlignment: HorizontalAlignment.Left
                            verticalAlignment: VerticalAlignment.Center
                            topPadding: ui.du(1.5)
                            bottomPadding: ui.du(1.5)
                            rightPadding: ui.du(3)

                            Label {
                                text: qsTr("Skip") + Retranslate.onLocaleOrLanguageChanged
                                textStyle.color: Color.create("#bfffffff")
                            }

                            gestureHandlers: [
                                TapHandler {
                                    onTapped: {
                                        sheet.finish(false);
                                    }
                                }
                            ]
                        }

                        Button {
                            horizontalAlignment: HorizontalAlignment.Right
                            verticalAlignment: VerticalAlignment.Center
                            appearance: ControlAppearance.Primary
                            text: (sheet.current < sheet.count - 1
                                    ? qsTr("Next")
                                    : qsTr("Done")) + Retranslate.onLocaleOrLanguageChanged
                            onClicked: {
                                if (sheet.current < sheet.count - 1) {
                                    sheet.go(sheet.current + 1);
                                } else {
                                    sheet.finish(false);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
