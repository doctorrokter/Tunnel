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
 *
 * bb-shared: the BlackBerry Cascades-Samples "repeater" component, wrapped in the bbshared
 * namespace and hardened with a couple of null guards (parent-not-a-Container).
 */
#include "Repeater.hpp"

#include <bb/cascades/DataModel>

#include <QDeclarativeComponent>
#include <QDeclarativeContext>

using namespace bb::cascades;

namespace bbshared {

Repeater::Repeater(Container* parent)
    : CustomControl(parent)
    , m_model(0)
    , m_delegate(0)
{
    // The Repeater itself is invisible — only the controls it generates are shown.
    setVisible(false);
}

Repeater::~Repeater()
{
}

QVariant Repeater::model() const
{
    return m_model;
}

void Repeater::setModel(const QVariant& model)
{
    if (m_model == model) {
        return;
    }
    m_model = model;
    clear();
    regenerate();
    emit modelChanged();
}

QDeclarativeComponent* Repeater::delegate() const
{
    return m_delegate;
}

void Repeater::setDelegate(QDeclarativeComponent* delegate)
{
    if (m_delegate == delegate) {
        return;
    }
    m_delegate = delegate;
    clear();
    regenerate();
    emit delegateChanged();
}

void Repeater::clear()
{
    // Remove the generated controls from their parent container, then delete them.
    Container* container = qobject_cast<Container*>(parent());
    if (container) {
        foreach (Control* control, m_controls) {
            container->remove(control);
        }
    }
    qDeleteAll(m_controls);
    m_controls.clear();
}

void Repeater::regenerate()
{
    if (!m_delegate) {
        return;
    }

    // The Repeater inserts its items into its PARENT container, right after itself.
    Container* container = qobject_cast<Container*>(parent());
    if (!container) {
        return; // a Repeater only works inside a Container
    }
    const int repeaterPosition = container->indexOf(this);

    if (m_model.type() == QVariant::Int || m_model.type() == QVariant::Double) {
        // N copies; the (1-based) index is the only per-item datum.
        const int counter = m_model.toInt();
        for (int i = 1; i <= counter; ++i) {
            QDeclarativeContext* context = new QDeclarativeContext(m_delegate->creationContext(), this);
            context->setContextProperty("index", i);
            context->setContextProperty("modelData", i);

            QObject* object = m_delegate->create(context);
            Control* control = qobject_cast<Control*>(object);
            if (!control) {
                if (object) {
                    object->deleteLater();
                }
                delete context;
                continue;
            }
            container->insert(repeaterPosition + i, control);
            m_controls.append(control);
        }
    } else if (m_model.type() == QVariant::List) {
        // One control per list entry; its value is `modelData`.
        const QVariantList list = m_model.toList();
        for (int i = 0; i < list.count(); ++i) {
            QDeclarativeContext* context = new QDeclarativeContext(m_delegate->creationContext(), this);
            context->setContextProperty("index", i + 1);
            context->setContextProperty("modelData", list.at(i));

            QObject* object = m_delegate->create(context);
            Control* control = qobject_cast<Control*>(object);
            if (!control) {
                if (object) {
                    object->deleteLater();
                }
                delete context;
                continue;
            }
            container->insert(repeaterPosition + i + 1, control);
            m_controls.append(control);
        }
    } else {
        QObject* modelObject = m_model.value<QObject*>();
        DataModel* dataModel = qobject_cast<DataModel*>(modelObject);
        if (dataModel) {
            // One control per top-level row; the row's key/value pairs become context properties.
            for (int i = 0; i < dataModel->childCount(QVariantList()); ++i) {
                QDeclarativeContext* context = new QDeclarativeContext(m_delegate->creationContext(), this);
                context->setContextProperty("index", i + 1);

                const QVariantMap map = dataModel->data(QVariantList() << i).toMap();
                foreach (const QString& key, map.keys()) {
                    context->setContextProperty(key, map.value(key));
                }

                QObject* object = m_delegate->create(context);
                Control* control = qobject_cast<Control*>(object);
                if (!control) {
                    if (object) {
                        object->deleteLater();
                    }
                    delete context;
                    continue;
                }
                container->insert(repeaterPosition + i + 1, control);
                m_controls.append(control);
            }
        }
    }
}

} // namespace bbshared
