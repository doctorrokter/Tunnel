import bb.cascades 1.4

/*
 * AlwaysOnRadios - one kind of profile on Settings > Connection (pages/ConnectionSettingsPage.qml):
 * "None" plus one radio per profile of the kind. One profile of each kind can be always on.
 *
 * Built like the Language page, driven by selectedIndex (the selected:/selectedValue route is flaky
 * on device).
 */
Container {
    id: root

    property string title: ""
    // Tailscale profiles, or WireGuard and AmneziaWG ones.
    property bool tailscale: false
    // The profile ids behind the options: [0] is "None".
    property variant ids: []

    function currentId() {
        return root.tailscale ? profiles.alwaysOnTailscale : profiles.alwaysOn;
    }

    horizontalAlignment: HorizontalAlignment.Fill

    Header {
        title: root.title
    }

    Container {
        horizontalAlignment: HorizontalAlignment.Fill
        topPadding: ui.du(dimens.gap)
        leftPadding: ui.du(dimens.pad)
        rightPadding: ui.du(dimens.pad)

        RadioGroup {
            id: group

            property bool ready: false

            Option {
                text: qsTr("None") + Retranslate.onLocaleOrLanguageChanged
                value: ""
            }

            onSelectedIndexChanged: {
                if (! group.ready) {
                    return; // the programmatic selection while it is built
                }
                if (selectedIndex < 0 || selectedIndex >= root.ids.length) {
                    return;
                }
                if (selectedIndex > 0) {
                    profiles.setAlwaysOn(root.ids[selectedIndex], true);
                } else if (root.currentId() !== "") {
                    profiles.setAlwaysOn(root.currentId(), false);
                }
            }

            onCreationCompleted: {
                var all = profiles.all;
                var current = root.currentId();
                var ids = [
                    ""
                ];
                var selected = 0;
                for (var i = 0; i < all.length; ++ i) {
                    if (all[i].tailscale !== root.tailscale) {
                        continue;
                    }
                    var option = optionDefinition.createObject();
                    option.text = all[i].name;
                    option.value = all[i].id;
                    group.add(option);
                    ids.push(all[i].id);
                    if (all[i].id === current) {
                        selected = ids.length - 1;
                    }
                }
                root.ids = ids;
                group.selectedIndex = selected;
                group.ready = true;
            }

            attachedObjects: [
                ComponentDefinition {
                    id: optionDefinition
                    content: Option {
                    }
                }
            ]
        }
    }
}
