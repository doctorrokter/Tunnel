import bb.cascades 1.4
import bb.shared 1.0

/*
 * OnboardingSlide - one slide of the setup guide (sheets/OnboardingSheet.qml): a white stock glyph in a
 * see-through circle, a title and a few lines, scrolled when they do not fit (a Q10). The slide is
 * transparent - the sheet draws the gradient under all of them. What a slide does - its buttons, a
 * status - goes in as its own children: they come after the text, at the slide's bottom, above the
 * sheet's dots and Next.
 */
Container {
    id: root

    // asset:///images/onboarding/<name>.png - white glyphs, made from the stock ones
    property string glyph: ""
    property string title: ""
    property string text: ""

    leftPadding: ui.du(dimens.pad)
    rightPadding: ui.du(dimens.pad)
    bottomPadding: ui.du(1)

    layout: StackLayout {
        orientation: LayoutOrientation.TopToBottom
    }

    ScrollView {
        horizontalAlignment: HorizontalAlignment.Fill
        verticalAlignment: VerticalAlignment.Fill
        scrollViewProperties.scrollMode: ScrollMode.Vertical

        layoutProperties: StackLayoutProperties {
            spaceQuota: 1
        }

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            topPadding: ui.du(6)
            bottomPadding: ui.du(2)

            AdvancedContainer {
                horizontalAlignment: HorizontalAlignment.Center
                preferredWidth: ui.du(18)
                preferredHeight: ui.du(18)
                cornerRadius: ui.du(9)
                color: Color.create("#26ffffff")
                layout: DockLayout {
                }

                ImageView {
                    horizontalAlignment: HorizontalAlignment.Center
                    verticalAlignment: VerticalAlignment.Center
                    preferredWidth: ui.du(10)
                    preferredHeight: ui.du(10)
                    scalingMethod: ScalingMethod.AspectFit
                    imageSource: root.glyph
                }
            }

            Label {
                horizontalAlignment: HorizontalAlignment.Fill
                topMargin: ui.du(4)
                text: root.title
                multiline: true
                textStyle.base: SystemDefaults.TextStyles.BigText
                textStyle.color: Color.White
                textStyle.textAlign: TextAlign.Center
            }

            Label {
                horizontalAlignment: HorizontalAlignment.Fill
                topMargin: ui.du(2)
                text: root.text
                multiline: true
                textStyle.base: SystemDefaults.TextStyles.BodyText
                textStyle.color: Color.create("#d9ffffff")
                textStyle.textAlign: TextAlign.Center
            }
        }
    }
}
