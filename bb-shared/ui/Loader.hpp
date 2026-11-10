/*
 * bb-shared / ui / Loader.hpp - a part of the page that EXISTS only while it is wanted. `import bb.shared 1.0`
 * (bb_shared_ui, registerUiTypes), then wrap what used to be hidden with `visible: false`:
 *
 *     Container {
 *         Label { text: "always" }
 *         Loader {
 *             active: msg.hasPoll              // made while true, gone while false
 *             PollBody { msg: root.msg }       // NOT made until then - no object, no binding, no picture
 *         }
 *     }
 *
 * Why: Cascades makes everything a document declares. `visible: false` takes an element out of the layout, but
 * it is still built, its bindings still run, its animations go on (KB 1.61: a list row with a hidden part is
 * made with it, every row). Qt 4.8's Cascades has no Loader of its own - QtQuick's cannot make a Cascades
 * control. This one makes the content when `active` turns true and deletes it when it turns false.
 *
 * THE CONTENT IS PLACED WHERE THE LOADER IS DECLARED - as its parent Container's child right after the Loader,
 * not inside a wrapper. So the content lays out exactly as if it were written there: its own alignment, margins,
 * spaceQuota and layoutProperties work in the parent's layout, a DockLayout overlay covers the page, and the
 * Loader itself is never visible and takes no room. (A Loader whose parent is not a Container - a Page's
 * content, a CustomControl's root - shows its content as its own root instead, and is visible while it has it.)
 *
 * What to make, one of:
 *  - the content written inside the Loader (its default property `sourceComponent`): the QML engine keeps it as
 *    a component - nothing in it is made with the page;
 *  - `sourceComponent: someComponent` - a Component declared elsewhere (QtQuick's `Component`);
 *  - `source: "Part.qml"` - a QML file, relative to the document the Loader is in.
 * `sourceComponent` wins when both are set. A change of either while the content exists makes it again.
 *
 * The content sees the document it is written in: its ids, the context properties, `ListItemData` in a list
 * row. Nothing of the Loader is put in its scope - name it by its id. `control` is the content (null while there
 * is none), `status` Null / Loading / Ready / Error with `errorString`, `loaded()` once it is in place.
 *
 * Made AT ONCE by default: `active = true; loader.control.openFor(x)` works on the next line. A Loader declared
 * with active true makes its content when the document completes - all its properties set, never half way.
 * `asynchronous: true` makes it on the next turn of the event loop instead (a tap answered first, `loaded()`
 * says when it is there); a deactivation before then cancels it.
 *
 * Unmade SAFELY from anywhere, its own content's handlers included (a picker's Close setting `active = false`):
 * the content leaves the screen and its container at once and is deleted with deleteLater, after the handler on
 * the stack has returned (KB 1.30: a control deleted under its own handler is a crash).
 *
 * Rules that stay the content's own: a connect() it makes to a long-lived object it must disconnect itself
 * (the object outlives it - KB "a stale QML handler aborts the caller"); don't set `visible` on the Loader -
 * `active` is the switch.
 */
#ifndef BBSHARED_LOADER_HPP
#define BBSHARED_LOADER_HPP

#include <bb/cascades/Container>
#include <bb/cascades/Control>
#include <bb/cascades/CustomControl>

#include <QtDeclarative/QDeclarativeComponent>

#include <QPointer>
#include <QString>
#include <QUrl>

namespace bbshared {

class Loader: public bb::cascades::CustomControl
{
    Q_OBJECT
    Q_ENUMS(Status)

    // Made while true, gone while false. True by default: a Loader with only a source just makes it.
    Q_PROPERTY(bool active READ active WRITE setActive NOTIFY activeChanged)
    // What to make: the content written inside the Loader (the default property), or a Component's id.
    Q_PROPERTY(QDeclarativeComponent* sourceComponent READ sourceComponent WRITE setSourceComponent
               NOTIFY sourceComponentChanged)
    // ...or a QML file. sourceComponent wins when both are set.
    Q_PROPERTY(QUrl source READ source WRITE setSource NOTIFY sourceChanged)
    // Made on the next turn of the event loop instead of at once.
    Q_PROPERTY(bool asynchronous READ asynchronous WRITE setAsynchronous NOTIFY asynchronousChanged)
    // The content, null while there is none.
    Q_PROPERTY(bb::cascades::Control* control READ control NOTIFY controlChanged)
    Q_PROPERTY(Status status READ status NOTIFY statusChanged)
    Q_PROPERTY(QString errorString READ errorString NOTIFY statusChanged)

    Q_CLASSINFO("DefaultProperty", "sourceComponent")

public:
    enum Status
    {
        Null,       // nothing made: inactive, or nothing to make
        Ready,      // the content is in place
        Loading,    // a source still loading, or an asynchronous make waiting for its turn
        Error       // could not be made - errorString says why (and the log)
    };

    explicit Loader(bb::cascades::Container* parent = 0);
    virtual ~Loader();

    bool active() const;
    void setActive(bool active);

    QDeclarativeComponent* sourceComponent() const;
    void setSourceComponent(QDeclarativeComponent* component);

    QUrl source() const;
    void setSource(const QUrl& source);

    bool asynchronous() const;
    void setAsynchronous(bool asynchronous);

    bb::cascades::Control* control() const;
    Status status() const;
    QString errorString() const;

    // Made by a QML document: nothing is made until it completes (its properties arrive one by one).
    virtual void classBegin();
    // The document is complete: every property is set, the first make may happen.
    virtual void componentComplete();

Q_SIGNALS:
    void activeChanged();
    void sourceComponentChanged();
    void sourceChanged();
    void asynchronousChanged();
    void controlChanged();
    void statusChanged();
    // The content is in place (control set, in its container, its creationCompleted run).
    void loaded();

private Q_SLOTS:
    void onDeferredMake();
    void onSourceStatusChanged();

private:
    QDeclarativeComponent* componentToMake();
    void sync();                    // what exists brought in line with the properties
    void make(QDeclarativeComponent* component);
    void place(bb::cascades::Control* control);
    void unmake();
    void dropOwnComponent();
    void setStatus(Status status, const QString& error);
    QString nameOf(const QDeclarativeComponent* component) const;   // for the log

    bool m_complete;                // not inside a QML document's making (a Loader made in C++ is complete at once)
    bool m_active;
    bool m_asynchronous;
    QPointer<QDeclarativeComponent> m_sourceComponent;
    QUrl m_source;
    QDeclarativeComponent* m_ownComponent;      // made from m_source, ours
    QPointer<QDeclarativeComponent> m_madeFrom; // what the content (or the pending make) is made of
    QPointer<bb::cascades::Control> m_control;  // the content
    QPointer<bb::cascades::Container> m_host;   // where it was put; 0 when it is our root
    bool m_makePending;             // an asynchronous make waits for its turn
    bool m_making;                  // inside make(): a change it causes is applied after it
    bool m_syncAgain;
    Status m_status;
    QString m_error;
};

} // namespace bbshared

#endif // BBSHARED_LOADER_HPP
