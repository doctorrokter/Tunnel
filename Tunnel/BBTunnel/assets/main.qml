/*
 * Copyright (c) 2013-2015 BlackBerry Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import bb.cascades 1.4
import bb.system 1.2
import bb.cascades.pickers 1.0
import "pages"
import "sheets"
import "cover"
import "leaving.js" as Leaving

// The connections at the bottom of the stack, a profile's page above them, the settings hub from the
// app menu (docs/APP.md). Everything a page cannot do alone is here: adding a profile (the source,
// the file picker, the QR scanner, the import sheet), the questions (a second "all traffic" profile,
// the daemon of an older package), the toasts, the Active Frame, and what comes from outside.
NavigationPane {
    id: nav

    // The settings hub is on the stack: the app menu stays off meanwhile (one hub at a time).
    property bool settingsOpen: false
    // A profile asked for before the list came (a tap on a notification at a cold start).
    property string pendingProfile: ""
    // The daemon's version was looked at on this connection (APP.md, section 9) - once.
    property bool versionChecked: false
    // Adding a profile, or a new .conf for `importProfile` ("replace").
    property string importMode: "new"
    property string importProfile: ""
    // The question of a second "all traffic" profile: the one that wanted it, the one that has it.
    property string conflictId: ""
    property string conflictHolder: ""
    // The profile just imported, or given a new .conf - the toast's and the dialog's.
    property string doneId: ""
    // The sources the dialog offers now, in its order (Tailscale only for a new profile).
    property variant sources: []
    // The scanner was opened from the Tailscale sheet: what it reads goes back there.
    property bool tailscaleScan: false
    // The app menu's sheets while they are up (Help, What's new): created on open, destroyed once closed, so a
    // closed one keeps no animation or binding working for nobody. Held here because createObject() gives them
    // no parent - this reference is what keeps them alive. Qt 4.8 reads an unset `variant` back as undefined,
    // so they are tested for truthiness, never against null.
    property variant helpSheetObj
    property variant changelogSheetObj
    property variant onboardingSheetObj

    // The app menu (swipe down), as in every app of ours: Settings, Help / About, What's new; and How to
    // start - the setup guide.
    Menu.definition: MenuDefinition {
        settingsAction: SettingsActionItem {
            onTriggered: {
                nav.openSettings();
            }
        }

        helpAction: HelpActionItem {
            onTriggered: {
                nav.openHelpSheet();
            }
        }

        actions: [
            ActionItem {
                title: qsTr("How to start") + Retranslate.onLocaleOrLanguageChanged
                imageSource: "asset:///images/onboarding/wifi_locked.png"
                onTriggered: {
                    nav.openOnboarding(false);
                }
            },
            ActionItem {
                title: qsTr("What's new") + Retranslate.onLocaleOrLanguageChanged
                imageSource: "asset:///images/ic_doctype_generic.png"
                onTriggered: {
                    nav.openChangelogSheet(changelog.all());
                }
            }
        ]
    }

    ConnectionsPage {
        id: connections
        onOpenProfile: {
            nav.openProfile(id);
        }
        onAddRequested: {
            nav.chooseSource("new", "");
        }
        onAddFrom: {
            nav.importMode = "new";
            nav.importProfile = "";
            nav.addFrom(source);
        }
        onSetupRequested: {
            nav.openOnboarding(false);
        }
    }

    attachedObjects: [
        ComponentDefinition {
            id: profileDef
            ProfilePage {
                id: profilePage
                onReplaceRequested: {
                    nav.chooseSource("replace", profileId);
                }
                onReloginRequested: {
                    nav.tailscaleScan = false;
                    tailscaleSheet.prepare("relogin", profileId, "");
                    tailscaleSheet.open();
                }
                // Its profile deleted - here or elsewhere: nothing left to show. Only while it is on
                // top - the user may have gone back already.
                onCloseRequested: {
                    if (nav.top === profilePage) {
                        nav.pop();
                    }
                }
            }
        },
        ComponentDefinition {
            id: qrDef
            QrScanPage {
                id: qrPage
                onFound: {
                    if (nav.top === qrPage) {
                        nav.pop();
                    }
                    // A Tailscale auth key: its sheet - the one that asked for the scan, as it was,
                    // or a new profile's.
                    if (importer.kind(text) === "tailscale-key") {
                        if (nav.tailscaleScan) {
                            tailscaleSheet.prepare(tailscaleSheet.mode, tailscaleSheet.profileId, text.trim());
                        } else {
                            tailscaleSheet.prepare("new", "", text.trim());
                        }
                        nav.tailscaleScan = false;
                        tailscaleSheet.open();
                        return;
                    }
                    nav.tailscaleScan = false;
                    nav.openImportSheet("qr", text, "", importer.nameFromConf(text));
                }
            }
        },
        // ---- Settings: the hub and its pages (BBTelega's pattern: a row pushes a page) ----
        ComponentDefinition {
            id: settingsDef
            SettingsPage {
                onConnectionSettingsRequested: {
                    nav.push(connectionDef.createObject());
                }
                onNotificationSettingsRequested: {
                    nav.push(notificationsDef.createObject());
                }
                onLanguageSettingsRequested: {
                    nav.push(languageDef.createObject());
                }
                onDiagnosticsRequested: {
                    nav.push(diagnosticsDef.createObject());
                }
            }
        },
        ComponentDefinition {
            id: connectionDef
            ConnectionSettingsPage {
            }
        },
        ComponentDefinition {
            id: notificationsDef
            NotificationSettingsPage {
            }
        },
        ComponentDefinition {
            id: languageDef
            LanguageSettingsPage {
            }
        },
        ComponentDefinition {
            id: diagnosticsDef
            DiagnosticsPage {
            }
        },
        ImportSheet {
            id: importSheet
            onImported: {
                nav.imported(doneId, doneMode, doneNote);
            }
            onTailscaleKey: {
                nav.tailscaleScan = false;
                tailscaleSheet.prepare("new", "", key);
                tailscaleSheet.open();
            }
        },
        TailscaleSheet {
            id: tailscaleSheet
            onDone: {
                nav.tailscaleDone(doneId, doneMode, doneHow);
            }
            onQrRequested: {
                nav.tailscaleScan = true;
                nav.push(qrDef.createObject());
            }
        },
        // ---- The app menu's sheets: created on open, destroyed once closed (openHelpSheet() ...) ----
        ComponentDefinition {
            id: helpSheetDef
            HelpSheet {
            }
        },
        ComponentDefinition {
            id: onboardingSheetDef
            OnboardingSheet {
            }
        },
        ComponentDefinition {
            id: changelogSheetDef
            ChangelogSheet {
            }
        },
        FilePicker {
            id: filePicker
            type: FileType.Other
            mode: FilePickerMode.Picker
            title: qsTr("Choose a profile file") + Retranslate.onLocaleOrLanguageChanged
            // A .vpn is an AmneziaVPN key as its app saves one.
            filter: [
                "*.conf",
                "*.vpn",
                "*.txt"
            ]
            onFileSelected: {
                if (selectedFiles.length > 0) {
                    nav.importFile(selectedFiles[0]);
                }
            }
        },
        // Where the profile comes from: a file, a QR code, pasted text - or, for a new one, a
        // Tailscale auth key.
        SystemListDialog {
            id: sourceDialog
            selectionMode: ListSelectionMode.Single
            confirmButton.label: qsTr("Next") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection && selectedIndices.length > 0) {
                    nav.addFrom(nav.sources[selectedIndices[0]]);
                }
            }
        },
        // A second "all traffic" profile: switch to it, or leave the first one.
        SystemDialog {
            id: conflictDialog
            title: qsTr("All traffic is taken") + Retranslate.onLocaleOrLanguageChanged
            confirmButton.label: qsTr("Switch") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection) {
                    profiles.switchTo(nav.conflictId, nav.conflictHolder);
                } else {
                    // The daemon keeps the refused tunnel as an error until it is taken down.
                    profiles.down(nav.conflictId);
                }
            }
        },
        // A new .conf for a tunnel that is up: it takes effect from its next start.
        SystemDialog {
            id: reconnectDialog
            title: qsTr("Configuration replaced") + Retranslate.onLocaleOrLanguageChanged
            body: qsTr("The tunnel uses it from its next start. Reconnect now?") + Retranslate.onLocaleOrLanguageChanged
            confirmButton.label: qsTr("Reconnect") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Later") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection) {
                    // In this order over the one connection: the daemon takes them one by one.
                    profiles.down(nav.doneId);
                    profiles.up(nav.doneId);
                }
            }
        },
        // "Profile added" - with "Connect".
        SystemToast {
            id: importedToast
            body: qsTr("Profile added") + Retranslate.onLocaleOrLanguageChanged
            button.label: qsTr("Connect") + Retranslate.onLocaleOrLanguageChanged
            button.enabled: true
            onFinished: {
                if (value === SystemUiResult.ButtonSelection) {
                    profiles.up(nav.doneId);
                }
            }
        },
        SystemToast {
            id: toast
        },
        // The Active Frame: the tunnels that are up, while the app is minimized (APP.md, section 10).
        SceneCover {
            id: cover
            content: StatusCover {
            }
        }
    ]

    onPopTransitionEnded: {
        if (page.objectName === "settings") {
            nav.settingsOpen = false;
            nav.syncMenu();
        }
        // A page that holds something of the daemon's (statistics, a profile's details) lets go.
        if (page.cleanup !== undefined) {
            page.cleanup();
        }
        page.destroy();
    }

    // navigateTo() pops several pages at once and reports them here, not in onPopTransitionEnded. Not from
    // its own list: it holds the pages as Page* values QML cannot use (no destroy(), no objectName, no
    // cleanup() - "TypeError: pages[i].destroy is not a function", KB 1.39) - from the pages backTo() took off
    // the pane before, kept in leaving.js (a JS module: a QML property would turn them into such values too).
    onNavigateToTransitionEnded: {
        var gone = Leaving.take();
        for (var i = 0; i < gone.length; i ++) {
            if (gone[i].objectName === "settings") {
                nav.settingsOpen = false;
            }
            if (gone[i].cleanup !== undefined) {
                gone[i].cleanup();
            }
            gone[i].destroy();
        }
        nav.syncMenu();
    }

    onCreationCompleted: {
        Application.setCover(cover);
        profiles.conflict.connect(nav.onConflict);
        profiles.failed.connect(nav.onFailed);
        profiles.loadedChanged.connect(nav.onLoaded);
        profiles.listChanged.connect(nav.onLoaded);
        profiles.readyChanged.connect(nav.checkDaemon);
        daemon.connectedChanged.connect(nav.onDaemonConnected);
        app.importFileRequested.connect(nav.importFile);
        app.openProfileRequested.connect(nav.openProfile);
        nav.syncMenu();
        nav.recordVersion();
        // What came from outside at a cold start, before this page was there to hear it.
        var path = app.takePendingImport();
        if (path !== "") {
            nav.importFile(path);
        }
        var id = app.takePendingProfile();
        if (id !== "") {
            nav.openProfile(id);
        }
        // The first start: the setup guide - unless the app was opened for something else.
        if (! settings.onboardingDone && path === "" && id === "") {
            nav.openOnboarding(true);
        }
    }

    // "What's new" once per upgrade; a fresh install only records the version (BBHealth's rule).
    function recordVersion() {
        var current = Application.applicationVersion;
        var lastSeen = settings.lastSeenVersion;
        if (lastSeen === "") {
            settings.lastSeenVersion = current;
        } else if (lastSeen !== current) {
            var entries = changelog.since(lastSeen);
            settings.lastSeenVersion = current;
            if (entries.length > 0) {
                nav.openChangelogSheet(entries);
            }
        }
    }

    // ---- The app menu's sheets (the property is cleared first, then the sheet released and destroyed) ----

    function openHelpSheet() {
        if (nav.helpSheetObj) {
            return;
        }
        nav.helpSheetObj = helpSheetDef.createObject();
        if (nav.helpSheetObj) {
            nav.helpSheetObj.closed.connect(nav.helpSheetClosed);
            nav.helpSheetObj.open();
        }
    }

    // The setup guide (sheets/OnboardingSheet.qml). FIRST_RUN: Done or Skip marks it seen.
    function openOnboarding(firstRun) {
        if (nav.onboardingSheetObj) {
            return;
        }
        nav.onboardingSheetObj = onboardingSheetDef.createObject();
        if (nav.onboardingSheetObj) {
            nav.onboardingSheetObj.firstRun = firstRun;
            nav.onboardingSheetObj.closed.connect(nav.onboardingSheetClosed);
            nav.onboardingSheetObj.addProfileRequested.connect(nav.onboardingAddProfile);
            nav.onboardingSheetObj.open();
        }
    }

    function onboardingSheetClosed() {
        var sheet = nav.onboardingSheetObj;
        nav.onboardingSheetObj = null;
        nav.dropSheet(sheet);
    }

    // Its last slide's "Add a profile": the sources, as the Add action offers them.
    function onboardingAddProfile() {
        nav.chooseSource("new", "");
    }

    function helpSheetClosed() {
        var sheet = nav.helpSheetObj;
        nav.helpSheetObj = null;
        nav.dropSheet(sheet);
    }

    // ENTRIES: the changelog to show - all of it from the menu, what is newer than the version last seen on
    // an upgrade. Already up: it just shows the new list.
    function openChangelogSheet(entries) {
        if (nav.changelogSheetObj) {
            nav.changelogSheetObj.entries = entries;
            return;
        }
        nav.changelogSheetObj = changelogSheetDef.createObject();
        if (nav.changelogSheetObj) {
            nav.changelogSheetObj.entries = entries;
            nav.changelogSheetObj.closed.connect(nav.changelogSheetClosed);
            nav.changelogSheetObj.open();
        }
    }

    function changelogSheetClosed() {
        var sheet = nav.changelogSheetObj;
        nav.changelogSheetObj = null;
        nav.dropSheet(sheet);
    }

    // A closed sheet goes for good: its cleanup() first if it has one (Cascades has no destruction hook to
    // unsubscribe in), then destroy() - the next open builds a fresh one.
    function dropSheet(sheet) {
        if (sheet) {
            if (sheet.cleanup !== undefined) {
                sheet.cleanup();
            }
            sheet.destroy();
        }
    }

    function openSettings() {
        if (nav.settingsOpen) {
            return;
        }
        nav.settingsOpen = true;
        nav.syncMenu();
        nav.push(settingsDef.createObject());
    }

    function syncMenu() {
        Application.menuEnabled = ! nav.settingsOpen;
    }

    // Back to PAGE in one move, every page over it taken off (navigateTo()): they are read off the pane first,
    // as the objects they are, for onNavigateToTransitionEnded (KB 1.39).
    function backTo(page) {
        var leaving = [];
        for (var i = nav.count() - 1; i >= 0; i --) {
            var onPane = nav.at(i);
            if (onPane === page) {
                break;
            }
            leaving.push(onPane);
        }
        Leaving.keep(leaving);
        nav.navigateTo(page);
    }

    function showToast(text) {
        toast.body = text;
        toast.show();
    }

    function openProfile(id) {
        if (! profiles.loaded) {
            // A tap on a notification at a cold start: the list is not in yet.
            nav.pendingProfile = id;
            return;
        }
        var profile = profiles.find(id);
        if (profile === null) {
            // Just added (a login by a link opens its page at once): the list brings it in a moment.
            nav.pendingProfile = id;
            return;
        }
        if (nav.top !== connections) {
            nav.backTo(connections);
        }
        var page = profileDef.createObject();
        page.profile = profile;
        nav.push(page);
    }

    // The list is in, or changed: a page that waited for its profile opens.
    function onLoaded() {
        if (nav.pendingProfile !== "" && profiles.loaded && profiles.find(nav.pendingProfile) !== null) {
            var id = nav.pendingProfile;
            nav.pendingProfile = "";
            nav.openProfile(id);
        }
    }

    // ---- Adding a profile, or a new .conf for one ------------------------------------------------

    function chooseSource(mode, profileId) {
        nav.importMode = mode;
        nav.importProfile = profileId;
        sourceDialog.title = mode === "replace"
                ? qsTr("Replace the configuration")
                : qsTr("Add a profile");
        sourceDialog.clearList();
        sourceDialog.appendItem(qsTr("From a file"));
        sourceDialog.appendItem(qsTr("Scan a QR code"));
        sourceDialog.appendItem(qsTr("Paste text"));
        if (mode === "new") {
            // The brand is no word to translate; the sheet offers a link or an auth key.
            sourceDialog.appendItem("Tailscale");
            nav.sources = [
                "file",
                "qr",
                "paste",
                "tailscale"
            ];
        } else {
            nav.sources = [
                "file",
                "qr",
                "paste"
            ];
        }
        sourceDialog.show();
    }

    function addFrom(source) {
        if (source === "file") {
            filePicker.open();
        } else if (source === "qr") {
            nav.tailscaleScan = false;
            nav.push(qrDef.createObject());
        } else if (source === "tailscale") {
            nav.tailscaleScan = false;
            tailscaleSheet.prepare("new", "", "");
            tailscaleSheet.open();
        } else {
            nav.openImportSheet("paste", "", "", "");
        }
    }

    // A Tailscale profile added, or logged in again. By a link: the tunnel gets the link at its start -
    // started (again) at once, and its page shows the link and its QR code. With a key: a new one is
    // offered "Connect" as any other; a new login of a tunnel that is up (it waits in an error)
    // reconnects at once - that is what it was for.
    function tailscaleDone(profileId, mode, how) {
        nav.doneId = profileId;
        if (how === "link") {
            var linked = profiles.find(profileId);
            if (linked !== null && linked.active) {
                // In this order over the one connection: the daemon takes them one by one.
                profiles.down(profileId);
            }
            profiles.up(profileId);
            // Logging in again from its own page: that page shows the link.
            if (nav.top === null || nav.top.profileId !== profileId) {
                nav.openProfile(profileId);
            }
            return;
        }
        if (mode === "relogin") {
            var profile = profiles.find(profileId);
            if (profile !== null && profile.active) {
                // In this order over the one connection: the daemon takes them one by one.
                profiles.down(profileId);
                profiles.up(profileId);
            }
            nav.showToast(qsTr("The new key is saved"));
            return;
        }
        importedToast.show();
    }

    // A file - picked, or opened "in Tunnel" from another app (then always a new profile).
    function importFile(path) {
        var text = importer.readFile(path);
        if (text === "") {
            var why = importer.lastError;
            if (why === "large") {
                nav.showToast(qsTr("This file is too big for a profile."));
            } else if (why === "binary") {
                nav.showToast(qsTr("This file is not a text file."));
            } else {
                nav.showToast(qsTr("This file cannot be read."));
            }
            return;
        }
        nav.openImportSheet("file", text, importer.fileName(path), importer.nameFromFile(path));
    }

    function openImportSheet(source, text, fileName, name) {
        importSheet.prepare(nav.importMode, nav.importProfile, source, text, fileName, name);
        importSheet.open();
        // Opened "in Tunnel" or from the notification of another flow: the next one is a new profile
        // unless someone says otherwise.
        nav.importMode = "new";
        nav.importProfile = "";
    }

    function imported(profileId, mode, note) {
        nav.doneId = profileId;
        if (mode === "replace") {
            var profile = profiles.find(profileId);
            if (note !== "" && profile !== null && profile.active) {
                reconnectDialog.show();
            } else {
                nav.showToast(qsTr("Configuration replaced"));
            }
            return;
        }
        importedToast.show();
    }

    // ---- The daemon's questions -------------------------------------------------------------------

    function onConflict(id, holder) {
        var wanted = profiles.find(id);
        var holding = profiles.find(holder);
        nav.conflictId = id;
        nav.conflictHolder = holder;
        conflictDialog.body = qsTr("All traffic already goes through \"%1\". Switch to \"%2\"?")
                .arg(holding !== null ? holding.name : holder)
                .arg(wanted !== null ? wanted.name : id);
        conflictDialog.show();
    }

    function onFailed(cmd, code, error) {
        connections.resetSwitches();
        if (code === 5) {
            nav.showToast(qsTr("Four tunnels are up already - that is as many as the phone has."));
        } else if (code === 3) {
            nav.showToast(qsTr("This profile is gone."));
        } else {
            nav.showToast(qsTr("The tunnel service refused: %1").arg(error));
        }
    }

    function onDaemonConnected() {
        if (! daemon.connected) {
            // The next connection may be another daemon (a restart): looked at again.
            nav.versionChecked = false;
        }
    }

    // After a reinstall the running daemon is the old binary (DAEMON section 12). It is not
    // restarted: on the phone the new copy starts only after a reboot, and a restart would leave no
    // service at all until then (APP section 9). Said once per connection.
    function checkDaemon() {
        if (! profiles.ready || ! daemon.connected || daemon.demo || nav.versionChecked) {
            return;
        }
        nav.versionChecked = true;
        if (daemon.daemonVersion === app.bundledDaemonVersion) {
            return;
        }
        nav.showToast(qsTr("The tunnel service updates when the phone restarts."));
    }
}
