/*
 * ChangelogSheet - "What's new" shown once per upgrade.
 *
 * main.qml sets `entries` (a list of { version, date, changes[] } from the
 * Changelog service) and opens the sheet. The entries are flattened into a
 * single ListView model: one "header" row per version, one "change" row per
 * bullet, so a variable number of changes renders without a Repeater.
 */

import bb.cascades 1.4

Sheet {
    id: sheet

    // Release entries newer than the last seen version (set before open()).
    property variant entries: []

    onEntriesChanged: {
        clModel.clear();
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            clModel.append({
                "type": "header",
                "version": e.version,
                "date": e.date
            });
            var changes = e.changes;
            for (var j = 0; j < changes.length; j++) {
                clModel.append({
                    "type": "change",
                    "text": changes[j]
                });
            }
        }
    }

    Page {
        titleBar: TitleBar {
            title: qsTr("What's new") + Retranslate.onLocaleOrLanguageChanged

            dismissAction: ActionItem {
                title: qsTr("Close") + Retranslate.onLocaleOrLanguageChanged
                onTriggered: {
                    sheet.close();
                }
            }
        }

        ListView {
            id: clList

            function itemType(data, indexPath) {
                return data.type;
            }

            dataModel: ArrayDataModel {
                id: clModel
            }
            

            listItemComponents: [
                ListItemComponent {
                    type: "header"
                    
                    Header {
                        title: qsTr("Version ") + ListItemData.version
                        subtitle: ListItemData.date
                    }
                },

                ListItemComponent {
                    type: "change"

                    Container {
                        topPadding: ui.du(dimens.pad / 2)
                        leftPadding: ui.du(dimens.pad)
                        rightPadding: ui.du(dimens.pad)
                        bottomPadding: ui.du(dimens.pad / 2)

                        layout: StackLayout {
                            orientation: LayoutOrientation.LeftToRight
                        }

                        Label {
                            text: "• "
                            textStyle.color: ui.palette.primary
                        }

                        Label {
                            text: ListItemData.text
                            multiline: true
                            layoutProperties: StackLayoutProperties {
                                spaceQuota: 1
                            }
                        }
                    }
                }
            ]
        }
    }
}
