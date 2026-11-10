// No ".pragma library": lupdate cannot parse it and would drop every string of this file.
//
// A profile's state in words (docs/APP.md, section 7): the list row's short line, the profile page's
// heading and its explanation, and whether the state is bad news. `p` is a Profile (client/Profiles.hpp):
// state - down | connecting | up | reconnecting | error; reason - "" or no_network, resolve,
// handshake, conf, conflict, tun, route, and a Tailscale tunnel's control, relay, approval, login,
// expired, removed, browser (a login link to open); detail - the daemon's own words, in English.
// A binding that calls these adds Retranslate.onLocaleOrLanguageChanged, so a language switch shows.

function typeName(p) {
    if (p.tailscale) {
        return "Tailscale";
    }
    return p.amnezia ? "AmneziaWG" : "WireGuard";
}

// The row's line under the name: "AmneziaWG - connected".
function row(p) {
    return typeName(p) + " - " + shortState(p);
}

function shortState(p) {
    if (p.reason === "no_network") {
        return qsTr("no network");
    }
    if (p.reason === "resolve") {
        return qsTr("server name not found");
    }
    if (p.reason === "handshake") {
        return qsTr("the server does not answer");
    }
    if (p.reason === "conf") {
        return qsTr("error in the configuration");
    }
    if (p.reason === "conflict") {
        return qsTr("another profile holds all traffic");
    }
    if (p.reason === "tun") {
        return qsTr("the tunnel could not be created");
    }
    if (p.reason === "route") {
        return qsTr("the routes could not be set");
    }
    if (p.reason === "control") {
        return qsTr("no connection to Tailscale");
    }
    if (p.reason === "relay") {
        return qsTr("waiting for the relay...");
    }
    if (p.reason === "approval") {
        return qsTr("waiting for approval");
    }
    if (p.reason === "login") {
        return qsTr("the login was not accepted");
    }
    if (p.reason === "expired") {
        return qsTr("the login expired");
    }
    if (p.reason === "removed") {
        return qsTr("removed from the tailnet");
    }
    if (p.reason === "browser") {
        return qsTr("waiting for a login at the link");
    }
    if (p.state === "up") {
        return qsTr("connected");
    }
    if (p.state === "connecting") {
        return qsTr("connecting...");
    }
    if (p.state === "reconnecting") {
        return qsTr("reconnecting...");
    }
    if (p.state === "error") {
        return qsTr("error");
    }
    return qsTr("off");
}

// The profile page's heading.
function title(p) {
    if (p.state === "up") {
        return qsTr("Connected");
    }
    if (p.state === "connecting") {
        return qsTr("Connecting...");
    }
    if (p.state === "reconnecting") {
        return qsTr("Reconnecting...");
    }
    if (p.state === "error") {
        return qsTr("Error");
    }
    return qsTr("Off");
}

// ...and what it means, "" when there is nothing to add.
function explanation(p) {
    if (p.reason === "no_network") {
        return qsTr("No network. The tunnel waits for it, and nothing goes past it meanwhile.");
    }
    if (p.reason === "resolve") {
        return qsTr("The server's name is not found. Check the server's address.") + (p.detail !== "" ? "\n" + p.detail : "");
    }
    if (p.reason === "handshake") {
        return qsTr("The server does not answer: a wrong key, address or protocol. From Russia, try an AmneziaWG profile.");
    }
    if (p.reason === "conf") {
        return qsTr("The configuration has an error.") + (p.detail !== "" ? "\n" + p.detail : "");
    }
    if (p.reason === "conflict") {
        return qsTr("Another profile already holds all traffic.");
    }
    if (p.reason === "tun" || p.reason === "route") {
        return qsTr("The tunnel could not be set up.") + (p.detail !== "" ? "\n" + p.detail : "");
    }
    if (p.reason === "control") {
        return qsTr("Tailscale's server cannot be reached. From Russia it does not answer at all.") + (p.detail !== "" ? "\n" + p.detail : "");
    }
    if (p.reason === "relay") {
        return qsTr("Logged in. The connection to Tailscale's relay is on its way.");
    }
    if (p.reason === "approval") {
        return qsTr("The device is in the tailnet, but an admin must approve it in the Tailscale admin console.");
    }
    if (p.reason === "login") {
        return qsTr("The login was not accepted: an auth key that expired, was used up or revoked, or a login refused. Log in again - by a link, or with a new key.") + (p.detail !== "" ? "\n" + p.detail : "");
    }
    if (p.reason === "expired") {
        return qsTr("The login expired. Log in again - by a link, or with a new auth key: a key with a tag does not expire.");
    }
    if (p.reason === "removed") {
        return qsTr("The device is no longer in the tailnet: an admin removed it, or the auth key was ephemeral and the device was offline for a while. Log in again - by a link, or with a new key that is not ephemeral.");
    }
    if (p.reason === "browser") {
        return qsTr("Log in at the link on a computer or another phone: scan the code below, or copy or share the link. The phone connects by itself once you are in.");
    }
    if (p.state === "reconnecting") {
        return qsTr("The network changed or the server went quiet. The routes stay: nothing goes past the tunnel meanwhile.");
    }
    return "";
}

// Bad news: said in red.
function bad(p) {
    return p.state === "error" || p.reason === "resolve" || p.reason === "handshake" || p.reason === "control";
}
