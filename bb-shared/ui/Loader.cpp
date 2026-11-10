/*
 * bb-shared / ui / Loader.cpp - see Loader.hpp.
 *
 * Grown from the BlackBerry Cascades-Samples "loader" (Apache License 2.0, Copyright (c) 2012, 2013 BlackBerry
 * Limited) and rebuilt for bb-shared. What changed against the sample, and why:
 *  - nothing is made before the QML document completes (the sample made it in setSource, with whatever
 *    properties had arrived by then - and with no engine at all if the context was not set yet);
 *  - `active`, the switch, and `asynchronous`;
 *  - the content goes into the parent Container beside the Loader, not inside a CustomControl wrapper - it lays
 *    out as if it were written there (the wrapper took its alignment, margins and spaceQuota out of the layout);
 *  - the content's context is deleted with it (the sample leaked one per load);
 *  - no context object: the sample put the Loader's every property into the content's scope, where a name like
 *    `visible` or `status` could silently resolve to the Loader;
 *  - unmade with remove + deleteLater, safe from the content's own handlers (KB 1.30), never deleted at once;
 *  - a change made while the content is being made - its creationCompleted setting the Loader - is applied after
 *    it, and a Loader deleted by its own content's handler is not touched again.
 */

/* Copyright (c) 2012, 2013  BlackBerry Limited.
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

#include "Loader.hpp"

#include <QtDeclarative/QDeclarativeContext>
#include <QtDeclarative/QDeclarativeEngine>
#include <QtDeclarative/QDeclarativeError>

#include <QElapsedTimer>
#include <QMetaObject>
#include <QStringList>
#include <QtDebug>

using namespace bb::cascades;

namespace bbshared {

// A make this long is said in the log (development builds); quicker ones are not - see make().
static const qint64 kSlowMakeMs = 50;

static QString errorsOf(const QDeclarativeComponent* component)
{
    QStringList lines;
    const QList<QDeclarativeError> errors = component->errors();
    for (int i = 0; i < errors.size(); ++i) {
        lines << errors.at(i).toString();
    }
    return lines.join(QLatin1String("; "));
}

Loader::Loader(Container* parent)
    : CustomControl(parent)
    , m_complete(true)
    , m_active(true)
    , m_asynchronous(false)
    , m_ownComponent(0)
    , m_makePending(false)
    , m_making(false)
    , m_syncAgain(false)
    , m_status(Null)
{
    // Never seen itself: its content goes into the parent Container beside it. Shown only when the content has to
    // be its root (a parent that is not a Container) - see place().
    setVisible(false);
}

Loader::~Loader()
{
    /*
     * NOTHING HERE TOUCHES THE CONTENT OR ITS CONTAINER.
     *
     * A Loader goes with the page around it, and its container with it - which deletes its children, the content
     * among them. Calling into a container that is being destroyed is exactly what must not happen, and there is no
     * way to tell from here that it is. A content that is our own root is our child and goes with us; our own
     * component is our child too.
     */
}

void Loader::classBegin()
{
    CustomControl::classBegin();
    m_complete = false;     // the properties arrive one by one from here: nothing is made until they all have
}

void Loader::componentComplete()
{
    CustomControl::componentComplete();
    m_complete = true;
    sync();
}

bool Loader::active() const
{
    return m_active;
}

void Loader::setActive(bool active)
{
    if (active == m_active) {
        return;
    }
    m_active = active;
    emit activeChanged();
    sync();
}

QDeclarativeComponent* Loader::sourceComponent() const
{
    return m_sourceComponent;
}

void Loader::setSourceComponent(QDeclarativeComponent* component)
{
    if (component == m_sourceComponent) {
        return;
    }
    m_sourceComponent = component;
    emit sourceComponentChanged();
    sync();     // a content made from the old one is made again from this
}

QUrl Loader::source() const
{
    return m_source;
}

void Loader::setSource(const QUrl& source)
{
    if (source == m_source) {
        return;
    }
    m_source = source;
    dropOwnComponent();
    emit sourceChanged();
    sync();
}

bool Loader::asynchronous() const
{
    return m_asynchronous;
}

void Loader::setAsynchronous(bool asynchronous)
{
    if (asynchronous == m_asynchronous) {
        return;
    }
    m_asynchronous = asynchronous;
    emit asynchronousChanged();
}

Control* Loader::control() const
{
    return m_control;
}

Loader::Status Loader::status() const
{
    return m_status;
}

QString Loader::errorString() const
{
    return m_error;
}

void Loader::setStatus(Status status, const QString& error)
{
    if (status == m_status && error == m_error) {
        return;
    }
    m_status = status;
    m_error = error;
    emit statusChanged();
}

QString Loader::nameOf(const QDeclarativeComponent* component) const
{
    if (component == 0) {
        return QLatin1String("nothing");
    }
    if (!component->url().isEmpty()) {
        return component->url().toString();
    }
    return QLatin1String("its inline content");
}

QDeclarativeComponent* Loader::componentToMake()
{
    if (m_sourceComponent) {
        return m_sourceComponent;
    }
    if (m_source.isEmpty()) {
        return 0;
    }
    if (m_ownComponent == 0) {
        QDeclarativeContext* context = QDeclarativeEngine::contextForObject(this);
        QDeclarativeEngine* engine = context ? context->engine() : 0;
        if (engine == 0) {
            setStatus(Error, QLatin1String("no QML engine to load ") + m_source.toString() + QLatin1String(" with"));
            qWarning() << "[Loader]" << m_error;
            return 0;
        }
        // A url read from QML is already resolved against the document the Loader is in.
        m_ownComponent = new QDeclarativeComponent(engine, m_source, this);
    }
    return m_ownComponent;
}

void Loader::dropOwnComponent()
{
    if (m_ownComponent != 0) {
        // Later, not now: it may be the one whose statusChanged is being handled.
        m_ownComponent->deleteLater();
        m_ownComponent = 0;
    }
}

void Loader::sync()
{
    if (!m_complete) {
        return;     // componentComplete calls this once everything is set
    }
    if (m_making) {
        m_syncAgain = true;     // applied when the make in progress is done
        return;
    }
    QDeclarativeComponent* wanted = m_active ? componentToMake() : 0;

    // What exists is made of something else, or nothing is wanted any more.
    if ((m_control || m_makePending) && (wanted == 0 || wanted != m_madeFrom)) {
        unmake();
    }
    if (wanted == 0) {
        if (m_status != Error || !m_active) {
            setStatus(Null, QString());
        }
        return;
    }
    if (m_control || m_makePending) {
        return;     // there already, or on its way
    }
    if (wanted->isLoading()) {
        // A source from far away (a local file or an asset loads at once). Asked again when it is in.
        connect(wanted, SIGNAL(statusChanged(QDeclarativeComponent::Status)),
                this, SLOT(onSourceStatusChanged()), Qt::UniqueConnection);
        setStatus(Loading, QString());
        return;
    }
    if (wanted->isError()) {
        const QString why = errorsOf(wanted);
        if (m_status != Error || m_error != why) {
            qWarning() << "[Loader] cannot make" << nameOf(wanted) << ":" << why;
        }
        setStatus(Error, why);
        return;
    }
    if (m_asynchronous) {
        m_makePending = true;
        m_madeFrom = wanted;
        setStatus(Loading, QString());
        QMetaObject::invokeMethod(this, "onDeferredMake", Qt::QueuedConnection);
        return;
    }
    make(wanted);
}

void Loader::onDeferredMake()
{
    if (!m_makePending) {
        return;     // cancelled meanwhile (or a later request already made it)
    }
    m_makePending = false;
    QDeclarativeComponent* wanted = m_active ? componentToMake() : 0;
    if (wanted == 0 || wanted != m_madeFrom || m_control) {
        m_madeFrom = 0;
        sync();     // the wish changed between the request and its turn
        return;
    }
    make(wanted);
}

void Loader::onSourceStatusChanged()
{
    sync();
}

void Loader::make(QDeclarativeComponent* component)
{
    // The content sees the document it is written in (its ids, the context properties, ListItemData in a list
    // row). A file loaded by url has no creation context: it gets the Loader's.
    QDeclarativeContext* outer = component->creationContext();
    if (outer == 0) {
        outer = QDeclarativeEngine::contextForObject(this);
    }
    if (outer == 0) {
        const QString why = QLatin1String("the Loader is not in a QML document: no context to make ")
                + nameOf(component) + QLatin1String(" in");
        qWarning() << "[Loader]" << why;
        setStatus(Error, why);
        return;
    }

    QPointer<Loader> self(this);
    QElapsedTimer clock;
    clock.start();
    m_making = true;
    m_madeFrom = component;
    QDeclarativeContext* context = new QDeclarativeContext(outer);
    QObject* object = component->beginCreate(context);
    Control* control = qobject_cast<Control*>(object);
    if (control == 0) {
        QString why;
        if (object != 0) {
            why = nameOf(component) + QLatin1String(" is not a control (") + QLatin1String(object->metaObject()->className())
                    + QLatin1String("): a Loader makes controls");
            component->completeCreate();
            delete object;
        } else {
            why = errorsOf(component);
            if (why.isEmpty()) {
                why = nameOf(component) + QLatin1String(" made nothing");
            }
        }
        delete context;
        m_making = false;
        m_madeFrom = 0;
        qWarning() << "[Loader] cannot make" << nameOf(component) << ":" << why;
        setStatus(Error, why);
        m_syncAgain = false;
        return;
    }

    // The context goes with what it made.
    context->setParent(control);
    m_control = control;
    // In place BEFORE it completes: its creationCompleted finds it where it belongs, as a written one would be.
    place(control);
    component->completeCreate();
    if (!self) {
        return;     // its creationCompleted deleted the page the Loader was in
    }
    m_making = false;
    /*
     * Only a SLOW make is said. A line per make cost as much as the make itself: a dev build's log line is written
     * to its file at once, ~9 ms on a Passport (BBTelega 451: a link preview made in 9-10 ms took 19 with its line),
     * and a feed makes a part per row. What a part costs is PartProbe's job (bb-shared debug).
     */
    const qint64 madeMs = clock.elapsed();
    if (madeMs >= kSlowMakeMs) {
        qDebug() << "[Loader] made" << control->metaObject()->className() << "of" << nameOf(component) << "in"
                 << madeMs << "ms (slow)";
    }

    setStatus(Ready, QString());
    emit controlChanged();
    if (!self) {
        return;
    }
    // A handler of controlChanged may have switched it off already: then there is nothing to announce.
    if (m_control == control) {
        emit loaded();
        if (!self) {
            return;
        }
    }
    if (m_syncAgain) {
        m_syncAgain = false;
        sync();     // what it changed while it was being made
    }
}

void Loader::place(Control* control)
{
    Container* host = qobject_cast<Container*>(parent());
    const int at = host ? host->indexOf(this) : -1;
    if (at >= 0) {
        // Right after the Loader: where it is written.
        host->insert(at + 1, control);
        m_host = host;
        return;
    }
    if (host != 0) {
        qWarning() << "[Loader] not among its Container's controls (attachedObjects?): its content is its own root";
    }
    // No Container around it: the content is the Loader's own root, and the Loader shows while it has it.
    m_host = 0;
    setRoot(control);
    setVisible(true);
}

void Loader::unmake()
{
    m_makePending = false;
    m_madeFrom = 0;
    Control* gone = m_control;
    m_control = 0;
    if (gone == 0) {
        return;
    }
    // Off the screen and out of the layout at once ...
    gone->setVisible(false);
    if (m_host && m_host->indexOf(gone) >= 0) {
        m_host->remove(gone);
    } else if (root() == gone) {
        setRoot(0);
        setVisible(false);
    }
    m_host = 0;
    // ... and deleted once the handler that may be running inside it has returned (KB 1.30).
    gone->deleteLater();
    emit controlChanged();
    setStatus(Null, QString());
}

} // namespace bbshared
