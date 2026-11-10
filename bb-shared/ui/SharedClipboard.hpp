/*
 * bb-shared / ui / SharedClipboard.hpp - copy plain text to the system clipboard from QML.
 *
 * Cascades has no clipboard in QML, and bb::system::Clipboard marks none of its methods invokable,
 * so every app carried its own few-line wrapper (BBTube's, copied on to BBHealth and BBTelega). This
 * one is a QML TYPE, so a component brings its own instance instead of counting on an app's context
 * property - which is what lets the "Buy me a coffee" card live in bb-shared:
 *
 *     import bb.shared 1.0
 *
 *     attachedObjects: [
 *         SharedClipboard {
 *             id: copier
 *         }
 *     ]
 *
 *     copier.copy("https://...");
 *
 * Compiled and registered only with CONFIG += bb_shared_coffee (bbshared::registerUiTypes() does the
 * registration). The name is not "Clipboard" on purpose: qmake puts every object file and moc output
 * of a project into ONE flat directory, and the apps with their own Clipboard.cpp would collide.
 */
#ifndef BBSHARED_SHAREDCLIPBOARD_HPP
#define BBSHARED_SHAREDCLIPBOARD_HPP

#include <QObject>
#include <QString>

namespace bbshared {

class SharedClipboard : public QObject
{
    Q_OBJECT
public:
    explicit SharedClipboard(QObject* parent = 0);
    virtual ~SharedClipboard() {}

    // Replaces the clipboard contents with `text` as text/plain. True on success.
    Q_INVOKABLE bool copy(const QString& text);
};

} // namespace bbshared

#endif // BBSHARED_SHAREDCLIPBOARD_HPP
