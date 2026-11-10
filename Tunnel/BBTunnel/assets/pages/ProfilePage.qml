import bb.cascades 1.4
import bb.system 1.2
import bb.shared 1.0
import "../shared"
import "../StateText.js" as States

/*
 * ProfilePage - one profile (docs/APP.md, section 4): its state in words, the statistics while the
 * page is open (watch stats=1 - app.statsWanted), and what profile.get says of it. Its actions:
 * connect / disconnect, rename, a new .conf (main.qml asks where from), always-on, copy the public
 * key, delete. The private key is never here: the daemon does not give it back.
 *
 * A Tailscale profile (docs/TAILSCALE.md, section 10) shows its tailnet instead of a .conf: this
 * device's name and addresses, the server, the login, the relay, and the tailnet's devices while
 * the tunnel is up (tailscale.nodes, asked again every few seconds and whenever the tunnel says
 * something changed) - a tap copies a device's address. "Log in again" takes the place of a new
 * .conf, "Copy my address" the place of the public key. While a login by a link waits (reason browser,
 * TAILSCALE.md section 11b), the link comes first: its QR code (bb-shared QRView) to scan with another
 * phone, the link itself, and copy / share it - to open on a computer.
 *
 * main.qml sets `profile` (a Profile - client/Profiles.hpp) before it pushes the page, and calls
 * cleanup() when it goes. A profile deleted meanwhile - here, by the service or over btctl - closes
 * the page (closeRequested).
 */
Page {
    id: page

    property variant profile: null
    // The id, kept: `profile` becomes null once the object is gone.
    property string profileId: ""
    // Statistics come every second: the devices are asked for every fifth.
    property int statsCount: 0
    // A share armed: onArmed triggers it once.
    property bool sharePending: false

    signal replaceRequested(string profileId)
    signal reloginRequested(string profileId)
    signal closeRequested()

    onProfileChanged: {
        if (page.profile !== null && page.profileId === "") {
            page.profileId = page.profile.id;
            profiles.loadDetails(page.profileId);
            app.statsWanted = true;
            profiles.listChanged.connect(page.checkGone);
            if (page.profile.tailscale) {
                page.profile.tailnetChanged.connect(page.loadNodes);
                page.profile.statsChanged.connect(page.onStats);
                page.loadNodes();
            }
        }
    }

    // Let go of what the page holds of the daemon's (main.qml, when the page is popped).
    function cleanup() {
        app.statsWanted = false;
        profiles.listChanged.disconnect(page.checkGone);
        if (page.profile !== null && page.profile.tailscale) {
            page.profile.tailnetChanged.disconnect(page.loadNodes);
            page.profile.statsChanged.disconnect(page.onStats);
        }
        if (page.profileId !== "") {
            profiles.releaseDetails(page.profileId);
        }
    }

    function loadNodes() {
        if (page.profile !== null && page.profile.active && daemon.connected) {
            profiles.loadNodes(page.profileId);
        }
    }

    function onStats() {
        page.statsCount = page.statsCount + 1;
        if (page.statsCount % 5 === 0) {
            page.loadNodes();
        }
    }

    // "100.64.0.7" of "100.64.0.7/32": an address to copy, from the tunnel or, while it is down, the
    // daemon's cache of the last netmap.
    function myAddress() {
        if (page.profile === null) {
            return "";
        }
        var live = page.profile.tailnet.addresses;
        if (live !== undefined && live.length > 0) {
            return live[0];
        }
        var cached = page.profile.detailsLoaded ? page.profile.details.address : undefined;
        if (cached !== undefined && cached.length > 0) {
            return cached[0].split("/")[0];
        }
        return "";
    }

    // The login link to open while a login by a link waits; "" otherwise.
    function loginLink() {
        if (page.profile === null || ! page.profile.tailscale || page.profile.reason !== "browser") {
            return "";
        }
        var link = page.profile.tailnet.authUrl;
        return link !== undefined ? link : "";
    }

    // The system's share list, with the link as text - an unbound Invocation: the user picks the app.
    function shareLink() {
        shareInvoke.query.data = page.loginLink();
        page.sharePending = true;
        // Re-arming is what raises onArmed - trigger() on a stale query goes nowhere.
        shareInvoke.query.updateQuery();
    }

    // "passport" of "passport.tail4ab2c.ts.net.": the name to show; the whole name stays below it.
    function shortName(fqdn) {
        return fqdn !== undefined && fqdn !== "" ? fqdn.split(".")[0] : "";
    }

    function onlineCount(nodes) {
        var n = 0;
        for (var i = 0; nodes !== undefined && i < nodes.length; i ++) {
            if (nodes[i].online === "1") {
                n ++;
            }
        }
        return n;
    }

    function checkGone() {
        if (profiles.find(page.profileId) === null) {
            page.closeRequested();
        }
    }

    // "12.4 MB" - in the units the phone shows file sizes in.
    function bytes(n) {
        if (n < 1024) {
            return qsTr("%1 B").arg(n);
        }
        if (n < 1024 * 1024) {
            return qsTr("%1 KB").arg((n / 1024).toFixed(1));
        }
        if (n < 1024 * 1024 * 1024) {
            return qsTr("%1 MB").arg((n / (1024 * 1024)).toFixed(1));
        }
        return qsTr("%1 GB").arg((n / (1024 * 1024 * 1024)).toFixed(2));
    }

    // "38 s ago", "5 min ago" - the last handshake, by the phone's clock.
    function ago(sec) {
        if (sec <= 0) {
            return qsTr("not yet");
        }
        var d = Math.max(0, Math.floor(Date.now() / 1000 - sec));
        if (d < 60) {
            return qsTr("%1 s ago").arg(d);
        }
        if (d < 3600) {
            return qsTr("%1 min ago").arg(Math.floor(d / 60));
        }
        return qsTr("%1 h ago").arg(Math.floor(d / 3600));
    }

    function joined(list) {
        return list !== undefined && list.length > 0 ? list.join("\n") : "";
    }

    titleBar: TitleBar {
        title: page.profile !== null ? page.profile.name : ""
    }

    actionBarAutoHideBehavior: ActionBarAutoHideBehavior.HideOnScroll
    actionBarVisibility: ChromeVisibility.Overlay

    actions: [
        ActionItem {
            title: (page.profile !== null && page.profile.active
                    ? qsTr("Disconnect")
                    : qsTr("Connect")) + Retranslate.onLocaleOrLanguageChanged
            imageSource: page.profile !== null && page.profile.active
                    ? "asset:///images/ic_stop.png"
                    : "asset:///images/ic_play.png"
            ActionBar.placement: ActionBarPlacement.Signature
            enabled: daemon.connected
            onTriggered: {
                if (page.profile.active) {
                    profiles.down(page.profileId);
                } else {
                    profiles.up(page.profileId);
                }
            }
        },
        ActionItem {
            title: qsTr("Rename") + Retranslate.onLocaleOrLanguageChanged
            imageSource: "asset:///images/ic_rename.png"
            enabled: daemon.connected
            onTriggered: {
                renamePrompt.inputField.defaultText = page.profile.name;
                renamePrompt.show();
            }
        },
        // A Tailscale profile has no .conf: its counterpart is a new login.
        ActionItem {
            title: (page.profile !== null && page.profile.tailscale
                    ? qsTr("Log in again")
                    : qsTr("Replace the configuration")) + Retranslate.onLocaleOrLanguageChanged
            imageSource: "asset:///images/ic_edit.png"
            enabled: daemon.connected
            onTriggered: {
                if (page.profile.tailscale) {
                    page.reloginRequested(page.profileId);
                } else {
                    page.replaceRequested(page.profileId);
                }
            }
        },
        ActionItem {
            title: (page.profile !== null && page.profile.alwaysOn
                    ? qsTr("Not always on")
                    : qsTr("Always on")) + Retranslate.onLocaleOrLanguageChanged
            imageSource: "asset:///images/ic_set_as_default.png"
            enabled: daemon.connected
            onTriggered: {
                profiles.setAlwaysOn(page.profileId, ! page.profile.alwaysOn);
            }
        },
        // Tailscale: this device's address in the tailnet - what the other devices reach it by.
        ActionItem {
            title: (page.profile !== null && page.profile.tailscale
                    ? qsTr("Copy my address")
                    : qsTr("Copy the public key")) + Retranslate.onLocaleOrLanguageChanged
            imageSource: "asset:///shared/images/ic_copy.png"
            enabled: page.profile !== null && (page.profile.tailscale
                    ? page.myAddress() !== ""
                    : page.profile.detailsLoaded && page.profile.details.public_key !== "")
            onTriggered: {
                if (page.profile.tailscale) {
                    if (clipboard.copy(page.myAddress())) {
                        copiedToast.body = qsTr("The address is copied");
                        copiedToast.show();
                    }
                } else if (clipboard.copy(page.profile.details.public_key)) {
                    copiedToast.body = qsTr("The public key is copied");
                    copiedToast.show();
                }
            }
        },
        DeleteActionItem {
            title: qsTr("Delete") + Retranslate.onLocaleOrLanguageChanged
            enabled: daemon.connected
            onTriggered: {
                deleteDialog.body = qsTr("Delete \"%1\"? Its keys go with it; a tunnel that is up is taken down first.").arg(page.profile.name);
                deleteDialog.show();
            }
        }
    ]

    ScrollView {
        scrollRole: ScrollRole.Main

        Container {
            horizontalAlignment: HorizontalAlignment.Fill
            bottomPadding: ui.du(15)

            // ---- The state -----------------------------------------------------------------------------
            Container {
                horizontalAlignment: HorizontalAlignment.Fill
                topPadding: ui.du(dimens.pad)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)
                bottomPadding: ui.du(dimens.gap)

                Label {
                    text: page.profile !== null ? States.title(page.profile) + Retranslate.onLocaleOrLanguageChanged : ""
                    textStyle.base: SystemDefaults.TextStyles.BigText
                    textStyle.color: page.profile !== null && States.bad(page.profile)
                            ? Color.Red
                            : (page.profile !== null && page.profile.state === "up" ? ui.palette.primary : ui.palette.textOnPlain)
                }

                Label {
                    visible: text !== ""
                    topMargin: 0
                    text: page.profile !== null ? States.explanation(page.profile) + Retranslate.onLocaleOrLanguageChanged : ""
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    multiline: true
                }

                // The statistics: while the tunnel is held (the daemon sends them while the page is open).
                Container {
                    visible: page.profile !== null && page.profile.active
                    topMargin: ui.du(dimens.gap)

                    Label {
                        bottomMargin: 0
                        text: page.profile !== null
                                ? qsTr("Received %1, sent %2").arg(page.bytes(page.profile.rxBytes)).arg(page.bytes(page.profile.txBytes)) + Retranslate.onLocaleOrLanguageChanged
                                : ""
                    }

                    // WireGuard: one server, one handshake. Tailscale: a handshake per device - the
                    // relay is what the whole tunnel hangs on.
                    Label {
                        visible: page.profile !== null && ! page.profile.tailscale
                        topMargin: 0
                        bottomMargin: 0
                        text: page.profile !== null
                                ? qsTr("Handshake: %1").arg(page.ago(page.profile.handshakeSec)) + Retranslate.onLocaleOrLanguageChanged
                                : ""
                        textStyle.color: ui.palette.secondaryTextOnPlain
                    }

                    Label {
                        visible: page.profile !== null && ! page.profile.tailscale && page.profile.endpointNow !== ""
                        topMargin: 0
                        text: page.profile !== null
                                ? qsTr("Server now: %1").arg(page.profile.endpointNow) + Retranslate.onLocaleOrLanguageChanged
                                : ""
                        textStyle.color: ui.palette.secondaryTextOnPlain
                    }

                    Label {
                        visible: page.profile !== null && page.profile.tailscale && page.profile.tailnet.relay !== undefined
                        topMargin: 0
                        text: page.profile !== null && page.profile.tailnet.relay !== undefined
                                ? (page.profile.tailnet.relayUp
                                        ? qsTr("Relay: %1, connected").arg(page.profile.tailnet.relay)
                                        : qsTr("Relay: %1, connecting...").arg(page.profile.tailnet.relay)) + Retranslate.onLocaleOrLanguageChanged
                                : ""
                        textStyle.color: ui.palette.secondaryTextOnPlain
                    }
                }
            }

            // ---- The login by a link: its QR code, the link, copy and share -----------------------------
            Container {
                visible: page.loginLink() !== ""
                horizontalAlignment: HorizontalAlignment.Fill
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)
                bottomPadding: ui.du(dimens.gap)

                // The code for a phone's camera; dark on its own white plate on any theme. Tunnel's icon in
                // the middle: the error correction goes High for it by itself.
                QRView {
                    text: page.loginLink()
                    horizontalAlignment: HorizontalAlignment.Center
                    preferredWidth: ui.du(50)
                    preferredHeight: ui.du(50)
                    color: Color.create("#11161c")
                    backgroundColor: Color.White
                    quietZone: 3
                    cornerRadius: ui.du(2)
                    moduleRadius: 0.5
                    eyeFrameRadius: 0.3
                    eyeBallRadius: 0.3
                    iconSource: "../icon.png"
                    iconSize: 0.2
                    iconRadius: 0.25
                }

                Label {
                    topMargin: ui.du(dimens.gap)
                    horizontalAlignment: HorizontalAlignment.Center
                    text: page.loginLink()
                    textStyle.base: SystemDefaults.TextStyles.SubtitleText
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    textStyle.textAlign: TextAlign.Center
                    multiline: true
                }

                Container {
                    topMargin: ui.du(dimens.gap)
                    horizontalAlignment: HorizontalAlignment.Fill
                    layout: StackLayout {
                        orientation: LayoutOrientation.LeftToRight
                    }

                    Button {
                        text: qsTr("Copy the link") + Retranslate.onLocaleOrLanguageChanged
                        layoutProperties: StackLayoutProperties {
                            spaceQuota: 1
                        }
                        onClicked: {
                            if (clipboard.copy(page.loginLink())) {
                                copiedToast.body = qsTr("The link is copied");
                                copiedToast.show();
                            }
                        }
                    }

                    Button {
                        text: qsTr("Share the link") + Retranslate.onLocaleOrLanguageChanged
                        layoutProperties: StackLayoutProperties {
                            spaceQuota: 1
                        }
                        onClicked: {
                            page.shareLink();
                        }
                    }
                }
            }

            // ---- The profile -----------------------------------------------------------------------------
            Header {
                title: qsTr("Profile") + Retranslate.onLocaleOrLanguageChanged
            }

            ActivityIndicator {
                visible: page.profile !== null && ! page.profile.detailsLoaded && daemon.connected
                running: visible
                horizontalAlignment: HorizontalAlignment.Center
                preferredWidth: ui.du(8)
                preferredHeight: ui.du(8)
            }

            // ---- A Tailscale profile: the tailnet, not a .conf ------------------------------------------
            Container {
                visible: page.profile !== null && page.profile.detailsLoaded && page.profile.tailscale
                horizontalAlignment: HorizontalAlignment.Fill

                PropListItem {
                    name: qsTr("Type") + Retranslate.onLocaleOrLanguageChanged
                    value: "Tailscale"
                }

                PropListItem {
                    visible: value !== ""
                    name: qsTr("Tailnet") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded
                            ? (page.profile.tailnet.tailnet !== undefined && page.profile.tailnet.tailnet !== ""
                                    ? page.profile.tailnet.tailnet
                                    : page.profile.details.tailnet)
                            : ""
                }

                PropListItem {
                    name: qsTr("This device") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded
                            ? (page.profile.details.node_name !== ""
                                    ? page.shortName(page.profile.details.node_name) + "\n" + page.profile.details.node_name
                                    : page.profile.details.hostname)
                            : ""
                }

                PropListItem {
                    visible: value !== ""
                    name: qsTr("Addresses") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded ? page.joined(page.profile.details.address) : ""
                }

                PropListItem {
                    name: qsTr("Server") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded
                            ? (page.profile.details.control === "https://controlplane.tailscale.com"
                                    ? qsTr("Tailscale (official)")
                                    : page.profile.details.control) + Retranslate.onLocaleOrLanguageChanged
                            : ""
                }

                PropListItem {
                    name: qsTr("Login") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded
                            ? (page.profile.details.login === "ok"
                                    ? qsTr("Logged in")
                                    : (page.profile.details.login === "link"
                                            ? qsTr("Not yet: by a link, at the connection")
                                            : qsTr("Not yet: at the first connection"))) + Retranslate.onLocaleOrLanguageChanged
                            : ""
                }

                PropListItem {
                    name: qsTr("Node key") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded ? page.profile.details.node_key : ""
                }
            }

            // ---- The tailnet's devices, while the tunnel is up --------------------------------------------
            Header {
                visible: page.profile !== null && page.profile.tailscale && page.profile.active
                title: qsTr("Devices") + Retranslate.onLocaleOrLanguageChanged
                subtitle: page.profile !== null && page.profile.tailscale
                        ? qsTr("%1 online").arg(page.onlineCount(page.profile.nodes)) + Retranslate.onLocaleOrLanguageChanged
                        : ""
            }

            Container {
                visible: page.profile !== null && page.profile.tailscale && page.profile.active && page.profile.nodes.length === 0
                horizontalAlignment: HorizontalAlignment.Fill
                topPadding: ui.du(1)
                leftPadding: ui.du(dimens.pad)
                rightPadding: ui.du(dimens.pad)

                Label {
                    text: (page.profile !== null && page.profile.state === "up"
                            ? qsTr("No other devices in the tailnet.")
                            : qsTr("The devices come with the tailnet's map.")) + Retranslate.onLocaleOrLanguageChanged
                    textStyle.color: ui.palette.secondaryTextOnPlain
                    multiline: true
                }
            }

            Container {
                visible: page.profile !== null && page.profile.tailscale && page.profile.active
                horizontalAlignment: HorizontalAlignment.Fill

                Repeater {
                    model: page.profile !== null ? page.profile.nodes : []

                    CustomListItem {
                        id: nodeRow

                        property variant node: modelData

                        dividerVisible: true

                        Container {
                            horizontalAlignment: HorizontalAlignment.Fill
                            topPadding: ui.du(1)
                            leftPadding: ui.du(dimens.pad)
                            rightPadding: ui.du(dimens.pad)
                            bottomPadding: ui.du(1)
                            layout: StackLayout {
                                orientation: LayoutOrientation.LeftToRight
                            }

                            // Online green, offline grey, unknown neither.
                            Container {
                                verticalAlignment: VerticalAlignment.Center
                                preferredWidth: ui.du(1.6)
                                preferredHeight: ui.du(1.6)
                                rightMargin: ui.du(2)
                                background: nodeRow.node.online === "1"
                                        ? Color.create("#3fb950")
                                        : (nodeRow.node.online === "0" ? Color.create("#8b949e") : Color.Transparent)
                            }

                            Container {
                                verticalAlignment: VerticalAlignment.Center
                                layoutProperties: StackLayoutProperties {
                                    spaceQuota: 1
                                }

                                Label {
                                    text: nodeRow.node.name
                                    bottomMargin: 0
                                }

                                Label {
                                    topMargin: 0
                                    text: nodeRow.node.addresses.length > 0 ? nodeRow.node.addresses[0] : ""
                                    textStyle.base: SystemDefaults.TextStyles.SubtitleText
                                    textStyle.color: ui.palette.secondaryTextOnPlain
                                }
                            }

                            Label {
                                verticalAlignment: VerticalAlignment.Center
                                text: (nodeRow.node.expired
                                        ? qsTr("expired")
                                        : (nodeRow.node.active
                                                ? qsTr("in use")
                                                : (nodeRow.node.online === "1"
                                                        ? qsTr("online")
                                                        : (nodeRow.node.online === "0" ? qsTr("offline") : "")))) + Retranslate.onLocaleOrLanguageChanged
                                textStyle.base: SystemDefaults.TextStyles.SubtitleText
                                textStyle.color: nodeRow.node.active ? ui.palette.primary : ui.palette.secondaryTextOnPlain
                            }

                            gestureHandlers: [
                                TapHandler {
                                    onTapped: {
                                        if (nodeRow.node.addresses.length > 0 && clipboard.copy(nodeRow.node.addresses[0])) {
                                            copiedToast.body = qsTr("%1: the address is copied").arg(nodeRow.node.name);
                                            copiedToast.show();
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }

            // ---- A WireGuard or AmneziaWG profile: its .conf ----------------------------------------------
            Container {
                visible: page.profile !== null && page.profile.detailsLoaded && ! page.profile.tailscale
                horizontalAlignment: HorizontalAlignment.Fill

                PropListItem {
                    name: qsTr("Type") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null ? States.typeName(page.profile) : ""
                }

                PropListItem {
                    name: qsTr("Public key") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded ? page.profile.details.public_key : ""
                }

                PropListItem {
                    name: qsTr("Addresses") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded ? page.joined(page.profile.details.address) : ""
                }

                PropListItem {
                    visible: value !== ""
                    name: qsTr("DNS") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded
                            ? page.joined(page.profile.details.dns) + (page.profile.details.dns_search !== "" ? "\n" + page.profile.details.dns_search : "")
                            : ""
                }

                PropListItem {
                    visible: page.profile !== null && page.profile.detailsLoaded && page.profile.details.dns.length === 0
                    name: qsTr("DNS") + Retranslate.onLocaleOrLanguageChanged
                    value: qsTr("The network's - past the tunnel") + Retranslate.onLocaleOrLanguageChanged
                }

                PropListItem {
                    name: (page.profile !== null && page.profile.detailsLoaded && page.profile.details.peers > 1
                            ? qsTr("Servers")
                            : qsTr("Server")) + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded ? page.joined(page.profile.details.endpoint) : ""
                }

                PropListItem {
                    name: qsTr("Routes") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile === null || ! page.profile.detailsLoaded
                            ? ""
                            : (page.profile.details.full
                                    ? qsTr("All traffic")
                                    : qsTr("Networks: %1").arg(page.profile.details.allowed_count) + "\n" + page.joined(page.profile.details.allowed)) + Retranslate.onLocaleOrLanguageChanged
                }

                PropListItem {
                    visible: value !== ""
                    name: qsTr("MTU") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded ? page.profile.details.mtu : ""
                }

                PropListItem {
                    visible: value !== ""
                    name: qsTr("Port") + Retranslate.onLocaleOrLanguageChanged
                    value: page.profile !== null && page.profile.detailsLoaded ? page.profile.details.listen_port : ""
                }
            }
        }
    }

    attachedObjects: [
        SharedClipboard {
            id: clipboard
        },
        Invocation {
            id: shareInvoke
            query {
                mimeType: "text/plain"
                invokeActionId: "bb.action.SHARE"
            }
            onArmed: {
                if (page.sharePending) {
                    page.sharePending = false;
                    shareInvoke.trigger(shareInvoke.query.invokeActionId);
                }
            }
        },
        SystemToast {
            id: copiedToast
            body: qsTr("The public key is copied") + Retranslate.onLocaleOrLanguageChanged
        },
        SystemPrompt {
            id: renamePrompt
            title: qsTr("Rename") + Retranslate.onLocaleOrLanguageChanged
            confirmButton.label: qsTr("Save") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection) {
                    var name = renamePrompt.inputFieldTextEntry().trim();
                    if (name !== "" && name !== page.profile.name) {
                        profiles.rename(page.profileId, name);
                    }
                }
            }
        },
        SystemDialog {
            id: deleteDialog
            title: qsTr("Delete the profile") + Retranslate.onLocaleOrLanguageChanged
            confirmButton.label: qsTr("Delete") + Retranslate.onLocaleOrLanguageChanged
            cancelButton.label: qsTr("Cancel") + Retranslate.onLocaleOrLanguageChanged
            onFinished: {
                if (value === SystemUiResult.ConfirmButtonSelection) {
                    profiles.remove(page.profileId);
                }
            }
        }
    ]
}
