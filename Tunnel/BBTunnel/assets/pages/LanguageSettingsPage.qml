import bb.cascades 1.4

Page {
    id: root

    titleBar: TitleBar {
        title: qsTr("Language") + Retranslate.onLocaleOrLanguageChanged
    }

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
    actionBarVisibility: ChromeVisibility.Overlay

    ScrollView {
        scrollRole: ScrollRole.Main

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            topPadding: ui.du(dimens.pad)
            leftPadding: ui.du(dimens.pad)
            rightPadding: ui.du(dimens.pad)
            bottomPadding: ui.du(15)

            // Registry-driven: "System" (follows the device locale) plus one radio per language
            // from settings.supportedLanguages() (the shared L10n table). Adding a language never
            // touches this file - it appears here automatically. Driven by selectedIndex, not
            // selected:/selectedValue (the latter is flaky on device and loses the selection).
            RadioGroup {
                id: langGroup

                property variant langs: settings.supportedLanguages() // [{ code, name }, ...]
                property bool ready: false

                // Index 0 = "System", 1 = English (the explicit default), 2..N = registry languages.
                Option {
                    text: qsTr("System") + Retranslate.onLocaleOrLanguageChanged
                    value: "system"
                }
                // English is the base/default language (ships no catalog), always shown explicitly.
                Option {
                    text: "English"
                    value: "en"
                }

                onSelectedIndexChanged: {
                    if (!langGroup.ready) {
                        return; // ignore the programmatic selection during build
                    }
                    if (selectedIndex === 0) {
                        settings.language = "system";
                        return;
                    }
                    if (selectedIndex === 1) {
                        settings.language = "en";
                        return;
                    }
                    var i = selectedIndex - 2; // 0 = System, 1 = English, then the registry languages
                    if (i >= 0 && i < langGroup.langs.length) {
                        settings.language = langGroup.langs[i].code;
                    }
                }

                onCreationCompleted: {
                    for (var i = 0; i < langGroup.langs.length; ++i) {
                        var o = optDef.createObject();
                        o.text = langGroup.langs[i].name; // native name, never translated
                        o.value = langGroup.langs[i].code;
                        langGroup.add(o);
                    }
                    // Reflect the stored setting: 0 = System, 1 = English, else registry index + 2.
                    var idx = 0;
                    var cur = settings.language;
                    if (cur === "en") {
                        idx = 1;
                    } else {
                        for (var j = 0; j < langGroup.langs.length; ++j) {
                            if (langGroup.langs[j].code === cur) {
                                idx = j + 2;
                                break;
                            }
                        }
                    }
                    langGroup.selectedIndex = idx;
                    langGroup.ready = true;
                }

                attachedObjects: [
                    ComponentDefinition {
                        id: optDef
                        content: Option {}
                    }
                ]
            }
        }
    }
}
