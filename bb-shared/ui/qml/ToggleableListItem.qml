/*
 * ToggleableListItem - a settings row with a switch: a title, an optional subtitle under it, a native
 * ToggleButton on the right, a divider beneath. Flipping the switch emits toggled(checked); the title
 * area is tappable on its own (tapped()). Colours are the theme's (ui.palette), the spacing is
 * `dimens` (bb_shared_dimens).
 *
 *   ToggleableListItem {
 *       title: qsTr("Only over Wi-Fi")
 *       checked: settings.cameraWifiOnly
 *       onToggled: settings.cameraWifiOnly = checked
 *   }
 *
 * Bind checked to the source of truth and write it back in onToggled. A flip the source refuses (a
 * switch that needs a folder first) is undone with reset().
 *
 * subtitleColor: the subtitle is the secondary text colour unless the row says otherwise (Tunnel's
 * connections colour their state line).
 *
 * BBTelega's row, then Syno's; moved here (2026-09-30) so the next app does not carry a third copy.
 */
import bb.cascades 1.4

Container {
    id: item

    property alias title: titleLabel.text
    // "" hides the line - it then takes no space.
    property alias subtitle: subtitleLabel.text
    property variant subtitleColor: ui.palette.secondaryTextOnPlain
    property bool checked: false
    property bool showDivider: true

    // A real flip of the switch by the user.
    signal toggled(bool checked)
    // The title area was tapped (not the switch).
    signal tapped()

    horizontalAlignment: HorizontalAlignment.Fill

    // The bound value moved: a user flip broke the switch's own binding, so it is set by hand.
    onCheckedChanged: {
        toggle.checked = checked;
    }

    // The switch back to the bound value (the flip was refused).
    function reset() {
        toggle.checked = item.checked;
    }

    Container {
        horizontalAlignment: HorizontalAlignment.Fill
        leftPadding: ui.du(dimens.pad)
        rightPadding: ui.du(dimens.pad)
        topPadding: ui.du(dimens.pad)
        bottomPadding: ui.du(dimens.pad)

        layout: StackLayout {
            orientation: LayoutOrientation.LeftToRight
        }

        Container {
            verticalAlignment: VerticalAlignment.Center
            rightMargin: ui.du(dimens.gap)

            layoutProperties: StackLayoutProperties {
                spaceQuota: 1
            }

            Label {
                id: titleLabel
                bottomMargin: 0
                multiline: true
                textStyle.base: SystemDefaults.TextStyles.PrimaryText
                textStyle.color: ui.palette.textOnPlain
            }

            Label {
                id: subtitleLabel
                topMargin: 0
                visible: text !== ""
                multiline: true
                textStyle.base: SystemDefaults.TextStyles.SubtitleText
                textStyle.color: item.subtitleColor
            }

            gestureHandlers: [
                TapHandler {
                    onTapped: {
                        item.tapped();
                    }
                }
            ]
        }

        ToggleButton {
            id: toggle
            verticalAlignment: VerticalAlignment.Center
            checked: item.checked
            onCheckedChanged: {
                if (checked !== item.checked) {
                    item.toggled(checked);
                }
            }
        }
    }

    Divider {
        visible: item.showDivider
        topMargin: 0
        bottomMargin: 0
    }
}
