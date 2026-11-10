/*
 * SettingsItem - a row of a settings hub: StandardListItem's layout (an icon, a title, a description
 * under it, a divider), but the icon takes the theme's text colour. The BB10 icons are white glyphs,
 * and StandardListItem shows its image as it is - invisible on the bright theme. The colours are the
 * theme's (ui.palette), the spacing is `dimens` (bb_shared_dimens).
 *
 *   SettingsItem {
 *       title: qsTr("Language") + Retranslate.onLocaleOrLanguageChanged
 *       description: ...
 *       imageSource: "asset:///images/ic_sb_network.png"
 *       onTapped: hub.languageSettingsRequested()
 *   }
 *
 * Moved here from Syno (2026-09-30), where it was born, so the next app does not carry a third copy.
 */
import bb.cascades 1.4

Container {
    id: item

    property alias title: titleLabel.text
    property alias description: descriptionLabel.text
    property alias imageSource: icon.imageSource

    signal tapped()

    horizontalAlignment: HorizontalAlignment.Fill

    Container {
        horizontalAlignment: HorizontalAlignment.Fill
        topPadding: ui.du(1.5)
        leftPadding: ui.du(dimens.pad)
        rightPadding: ui.du(dimens.pad)
        bottomPadding: ui.du(1.5)

        layout: StackLayout {
            orientation: LayoutOrientation.LeftToRight
        }

        ImageView {
            id: icon
            verticalAlignment: VerticalAlignment.Center
            preferredWidth: ui.du(8)
            preferredHeight: ui.du(8)
            scalingMethod: ScalingMethod.AspectFit
            filterColor: ui.palette.textOnPlain
        }

        Container {
            verticalAlignment: VerticalAlignment.Center
            leftPadding: ui.du(2)

            layoutProperties: StackLayoutProperties {
                spaceQuota: 1
            }

            Label {
                id: titleLabel
                bottomMargin: 0
                textStyle.base: SystemDefaults.TextStyles.PrimaryText
            }

            Label {
                id: descriptionLabel
                visible: text !== ""
                topMargin: 0
                textStyle.base: SystemDefaults.TextStyles.SubtitleText
                textStyle.color: ui.palette.secondaryTextOnPlain
            }
        }
    }

    Divider {
        topMargin: 0
        bottomMargin: 0
    }

    gestureHandlers: [
        TapHandler {
            onTapped: {
                item.tapped();
            }
        }
    ]
}
