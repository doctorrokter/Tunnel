// The pages main.qml's backTo() takes off the pane (whatever is over the connections when a profile is opened
// from outside), kept as the objects they are until navigateTo()'s transition ends, then cleaned up and
// destroyed there. Not in a QML property: a `property variant` turns a list of pages into values QML cannot
// use - no destroy(), no objectName, no cleanup() (KB 1.39); a JS module's variable keeps them as they are.
// BerryAmp's leaving.js.

var pages = [];

function keep(list) {
    pages = list;
}

// The pages kept, and none kept any more.
function take() {
    var taken = pages;
    pages = [];
    return taken;
}
