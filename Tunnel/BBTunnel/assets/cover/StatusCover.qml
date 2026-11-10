import bb.cascades 1.4
import bb.shared 1.0
import "../StateText.js" as States

/*
 * StatusCover - the Active Frame (docs/APP.md, section 10): the tunnels the daemon holds, up to three,
 * each with its state; "Not connected" when none. No traffic: statistics are off while the app is
 * minimized, so the phone is not woken for them. Passive - bound to profiles.active and each
 * profile's state, no timer (BBTelega's and BBTube's way). The simulator draws covers black: look
 * at it on a phone.
 */
Container {
    horizontalAlignment: HorizontalAlignment.Fill
    verticalAlignment: VerticalAlignment.Fill
    topPadding: ui.du(2)
    leftPadding: ui.du(2)
    rightPadding: ui.du(2)
    bottomPadding: ui.du(2)
    background: Color.create("#1b2430")

//    Label {
//        text: "Tunnel"
//        textStyle.base: SystemDefaults.TextStyles.TitleText
//        textStyle.color: Color.White
//        bottomMargin: ui.du(1)
//    }

    Label {
        visible: profiles.active.length === 0
        text: qsTr("Not connected") + Retranslate.onLocaleOrLanguageChanged
        textStyle.color: Color.create("#9aa7b4")
    }

    Container {
        horizontalAlignment: HorizontalAlignment.Fill

        Repeater {
            model: profiles.active.slice(0, 3)

            Container {
                id: coverRow

                property variant profile: modelData

                bottomMargin: ui.du(1)

                Label {
                    text: coverRow.profile.name
                    textStyle.color: Color.White
                    textStyle.fontWeight: FontWeight.W500
                    bottomMargin: 0
                }

                Label {
                    topMargin: 0
                    text: States.shortState(coverRow.profile) + Retranslate.onLocaleOrLanguageChanged
                    textStyle.base: SystemDefaults.TextStyles.SubtitleText
                    textStyle.color: coverRow.profile.state === "up"
                            ? Color.create("#6fcf97")
                            : (States.bad(coverRow.profile) ? Color.create("#ff6b6b") : Color.create("#9aa7b4"))
                }
            }
        }
    }
}
