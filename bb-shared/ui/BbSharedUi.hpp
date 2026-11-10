/*
 * bb-shared / ui / BbSharedUi.hpp - one place that registers bb-shared's QML UI types. The app calls
 * bbshared::registerUiTypes() ONCE at startup (before loading QML that uses them) and then writes
 * `import bb.shared 1.0` in its QML. This copy registers only the types Tunnel uses.
 *
 * GUI-only (needs Cascades / QtDeclarative) - the headless service never includes this. bb-shared.pri
 * compiles the ui/ part only under CONFIG += bb_shared_ui.
 *
 * SharedClipboard (the "Buy me a coffee" card's copy button) is registered only when the app also has
 * CONFIG += bb_shared_coffee, which defines BBSHARED_COFFEE and compiles it; QRView likewise under
 * CONFIG += bb_shared_qr (BBSHARED_QR).
 */
#ifndef BBSHARED_BBSHAREDUI_HPP
#define BBSHARED_BBSHAREDUI_HPP

#include "AdvancedContainer.hpp"
#include "Loader.hpp"
#include "Repeater.hpp"

#ifdef BBSHARED_COFFEE
#include "SharedClipboard.hpp"
#endif

#ifdef BBSHARED_QR
#include "QRView.hpp"
#endif

#include <bb/cascades/Container>
#include <QtDeclarative/qdeclarative.h>

namespace bbshared {

inline void registerUiTypes()
{
    // The Cascades base's REVISIONED properties, opened on our subclasses. QML gives a type registered here
    // its base classes' properties only up to the revisions registered for THIS module - with none, setting a
    // revisioned one fails the whole document: "is not available due to component versioning".
    // Container: accessibility (2), navigation (4).
    qmlRegisterRevision<bb::cascades::Container, 4>("bb.shared", 1, 0);
    qmlRegisterType<bbshared::Repeater>("bb.shared", 1, 0, "Repeater");
    // a Container with rounded corners and a border, all in C++
    qmlRegisterType<bbshared::AdvancedContainer>("bb.shared", 1, 0, "AdvancedContainer");
    // a part of the page that exists only while it is wanted - made on `active`, deleted after (not visible: false)
    qmlRegisterType<bbshared::Loader>("bb.shared", 1, 0, "Loader");
#ifdef BBSHARED_COFFEE
    qmlRegisterType<bbshared::SharedClipboard>("bb.shared", 1, 0, "SharedClipboard");
#endif
#ifdef BBSHARED_QR
    // a QR code drawn in C++ off the UI thread: colours, shapes, an icon, a badge, a PNG to share
    qmlRegisterType<bbshared::QRView>("bb.shared", 1, 0, "QRView");
#endif
}

} // namespace bbshared

#endif // BBSHARED_BBSHAREDUI_HPP
