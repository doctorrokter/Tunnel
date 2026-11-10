/*
 * BuyMeACoffee - the "Buy me a coffee" card of every app's Help sheet (bb-shared).
 *
 * The card each app used to carry a copy of, with its images and its copy-link helper, moved here
 * as it was: the warm card with the cup and the rising steam (tap -> the Boosty page in the system
 * browser), then the link itself with a copy button, because the BB10 browser does not always
 * manage to open it.
 *
 *   import "shared"
 *   BuyMeACoffee {
 *       linkColor: theme.accent       // optional: the app's own colours outside the card
 *   }
 *
 * Needs CONFIG += bb_shared_ui bb_shared_coffee (its plates are AdvancedContainers), ui/images packed as
 * assets/shared/images, and this file listed for the app's lupdate - bb-shared README, section 5.
 * Its strings are translated in the APP's catalog, context "BuyMeACoffee".
 *
 * The card keeps its own warm palette (hardcoded hex), so it reads the same in light and dark themes.
 * `animated` runs the cup and the steam. A host that stays alive while hidden - a Sheet kept in
 * attachedObjects - sets it in onOpened / onClosed, so nothing animates off screen.
 */
import bb.cascades 1.4
import bb.system 1.2
import bb.shared 1.0

Container {
    id: root

    // The page the card and the link open.
    property string url: "https://boosty.to/doctorrokter/donate"

    // Spacing in du - what dimens.pad / dimens.gap are in the apps that have them.
    property real pad: 2
    property real gap: 2

    // The host's colours for the parts outside the card.
    property variant textColor: ui.palette.textOnPlain
    property variant linkColor: ui.palette.primary
    property variant iconColor: ui.palette.textOnPlain

    property bool animated: true

    horizontalAlignment: HorizontalAlignment.Fill

    onAnimatedChanged: {
        if (root.animated) {
            steamAnim.play();
            cupBob.play();
        } else {
            steamAnim.stop();
            cupBob.stop();
        }
    }

    function openLink() {
        boostyInvoke.trigger(boostyInvoke.query.invokeActionId);
    }

    // The whole card is tappable and opens the Boosty page.
    AdvancedContainer {
        horizontalAlignment: HorizontalAlignment.Fill
        verticalAlignment: VerticalAlignment.Fill
        color: Color.create("#ffb74d")
        cornerRadius: ui.du(2)
        topPadding: ui.du(root.pad)
        leftPadding: ui.du(root.pad)
        rightPadding: ui.du(root.pad)
        bottomPadding: ui.du(root.pad)
        bottomMargin: ui.du(root.gap)
        layout: StackLayout {
            orientation: LayoutOrientation.LeftToRight
        }

        gestureHandlers: [
            TapHandler {
                onTapped: {
                    root.openLink();
                }
            }
        ]

        // Cup + rising steam, stacked vertically.
        Container {
            preferredWidth: ui.du(14)
            verticalAlignment: VerticalAlignment.Center
            horizontalAlignment: HorizontalAlignment.Center

            ImageView {
                id: steamImg
                imageSource: "asset:///shared/images/ic_coffee_steam.png"
                preferredWidth: ui.du(3)
                preferredHeight: ui.du(5)
                scalingMethod: ScalingMethod.AspectFit
                horizontalAlignment: HorizontalAlignment.Center
                opacity: 0.0

                onCreationCompleted: {
                    if (root.animated) {
                        steamAnim.play();
                    }
                }

                animations: [
                    SequentialAnimation {
                        id: steamAnim

                        animations: [
                            ParallelAnimation {
                                TranslateTransition {
                                    target: steamImg
                                    fromY: ui.du(1)
                                    toY: -ui.du(1.5)
                                    duration: 2000
                                }
                                FadeTransition {
                                    target: steamImg
                                    fromOpacity: 0.0
                                    toOpacity: 0.85
                                    duration: 900
                                }
                            },
                            FadeTransition {
                                target: steamImg
                                fromOpacity: 0.85
                                toOpacity: 0.0
                                duration: 900
                            }
                        ]

                        // Loops. A stop() ends it too, hence the check.
                        onEnded: {
                            if (root.animated) {
                                steamAnim.play();
                            }
                        }
                    }
                ]
            }

            ImageView {
                id: cupImg
                imageSource: "asset:///shared/images/ic_coffee_cup.png"
                preferredWidth: ui.du(12)
                preferredHeight: ui.du(12)
                scalingMethod: ScalingMethod.AspectFit
                horizontalAlignment: HorizontalAlignment.Center

                onCreationCompleted: {
                    if (root.animated) {
                        cupBob.play();
                    }
                }

                animations: [
                    SequentialAnimation {
                        id: cupBob

                        animations: [
                            TranslateTransition {
                                target: cupImg
                                fromY: 0
                                toY: -ui.du(0.75)
                                duration: 1400
                                easingCurve: StockCurve.SineInOut
                            },
                            TranslateTransition {
                                target: cupImg
                                fromY: -ui.du(0.75)
                                toY: 0
                                duration: 1400
                                easingCurve: StockCurve.SineInOut
                            }
                        ]

                        onEnded: {
                            if (root.animated) {
                                cupBob.play();
                            }
                        }
                    }
                ]
            }
        }

        // Copy + pill button.
        Container {
            leftMargin: ui.du(root.gap)
            verticalAlignment: VerticalAlignment.Center
            layoutProperties: StackLayoutProperties {
                spaceQuota: 1
            }

            Label {
                text: qsTr("Enjoying") + Retranslate.onLocaleOrLanguageChanged + " " + Application.applicationName + "?"
                multiline: true
                textStyle.color: Color.create("#3e2723")
                textStyle.fontWeight: FontWeight.Bold
                textStyle.base: SystemDefaults.TextStyles.PrimaryText
            }

            Label {
                text: qsTr("It's free and made with love. If it brightened your day, treat me to a coffee!") + Retranslate.onLocaleOrLanguageChanged
                multiline: true
                topMargin: ui.du(root.gap)
                textStyle.color: Color.create("#5d4037")
                textStyle.base: SystemDefaults.TextStyles.BodyText
            }

            AdvancedContainer {
                color: Color.create("#4e342e")
                cornerRadius: ui.du(3)
                topMargin: ui.du(root.gap)
                leftPadding: ui.du(2)
                rightPadding: ui.du(2)
                topPadding: ui.du(1)
                bottomPadding: ui.du(2)

                Label {
                    text: qsTr("☕  Buy me a coffee") + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: Color.create("#fff3e0")
                    textStyle.fontWeight: FontWeight.Bold
                    horizontalAlignment: HorizontalAlignment.Center
                }
            }
        }
    }

    Label {
        text: qsTr("Donate on Boosty:") + Retranslate.onLocaleOrLanguageChanged
        textStyle.color: root.textColor
    }

    // The link itself, copyable: the BB10 browser does not always manage to open it.
    Container {
        horizontalAlignment: HorizontalAlignment.Fill
        layout: StackLayout {
            orientation: LayoutOrientation.LeftToRight
        }

        Label {
            text: root.url
            multiline: true
            verticalAlignment: VerticalAlignment.Center
            textStyle.color: root.linkColor
            textStyle.fontWeight: FontWeight.W500
            layoutProperties: StackLayoutProperties {
                spaceQuota: 1
            }

            gestureHandlers: [
                TapHandler {
                    onTapped: {
                        root.openLink();
                    }
                }
            ]
        }

        ImageView {
            imageSource: "asset:///shared/images/ic_copy.png"
            preferredWidth: ui.du(5)
            preferredHeight: ui.du(5)
            verticalAlignment: VerticalAlignment.Center
            filterColor: root.iconColor

            gestureHandlers: [
                TapHandler {
                    onTapped: {
                        if (copier.copy(root.url)) {
                            copyToast.show();
                        }
                    }
                }
            ]
        }
    }

    attachedObjects: [
        Invocation {
            id: boostyInvoke
            query {
                uri: root.url
                invokeActionId: "bb.action.OPEN"
                invokeTargetId: "sys.browser"
            }
        },
        SharedClipboard {
            id: copier
        },
        SystemToast {
            id: copyToast
            body: qsTr("Link copied to clipboard") + Retranslate.onLocaleOrLanguageChanged
        }
    ]
}
