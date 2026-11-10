/*
 * PropListItem - one line of a properties page: what it is (the name, small) and its value under it,
 * with a divider. A CustomListItem, so it works in a ListView's ListItemComponent and in a plain
 * Container alike. The spacing across is `dimens` (bb_shared_dimens).
 *
 *   PropListItem {
 *       name: qsTr("Server")
 *       value: "vpn.example.com:51820"
 *   }
 *
 * Syno's row; moved here (2026-09-30) so the next app does not carry a third copy.
 */
import bb.cascades 1.4

CustomListItem {
    id: root

    property string name: ""
    property string value: ""

    dividerVisible: true

    Container {
        horizontalAlignment: HorizontalAlignment.Fill
        verticalAlignment: VerticalAlignment.Center
        topPadding: ui.du(1)
        leftPadding: ui.du(dimens.pad)
        rightPadding: ui.du(dimens.pad)
        bottomPadding: ui.du(1)

        Label {
            text: root.name
            textStyle.base: SystemDefaults.TextStyles.SubtitleText
            bottomMargin: 0
        }

        Label {
            topMargin: 0
            text: root.value
            multiline: true
        }
    }
}
