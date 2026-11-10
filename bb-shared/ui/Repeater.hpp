/*
 * bb-shared / ui / Repeater — the "Repeater" that Cascades does not ship. Cascades has NO stock
 * Repeater (a QtQuick Repeater can't instantiate bb::cascades::Control), so this is the standard
 * fix: an (invisible) CustomControl that instantiates its `delegate` once per `model` item and
 * inserts the results INTO ITS PARENT Container. Use it for BOUNDED inline lists — chips, rails,
 * a handful of rows in a ScrollView — NOT long scrolling lists (it builds every item eagerly, no
 * recycling; those stay on ListView). The parent MUST be a Container.
 *
 *   Container {
 *       Repeater {
 *           model: 5            // int (N copies), a QVariantList, or a bb::cascades::DataModel
 *           Label { text: qsTr("Row ") + index }   // delegate is the default property
 *       }
 *   }
 *
 * In the delegate: `index` is available (NB: 1-based, matching the BlackBerry sample); a
 * QVariantList item is `modelData`; a DataModel row's map keys are exposed directly as properties.
 *
 * This is the BlackBerry Cascades-Samples "repeater" component (Apache License 2.0), adapted only
 * for bb-shared: wrapped in the bbshared namespace and hardened with a couple of null guards.
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
#ifndef BBSHARED_REPEATER_HPP
#define BBSHARED_REPEATER_HPP

#include <bb/cascades/Container>
#include <bb/cascades/CustomControl>

#include <QVariant>
#include <QList>

class QDeclarativeComponent;

namespace bbshared {

class Repeater : public bb::cascades::CustomControl
{
    Q_OBJECT

    // QVariant so the caller can pass an int, a QVariantList, or a DataModel.
    Q_PROPERTY(QVariant model READ model WRITE setModel NOTIFY modelChanged)
    // The declarative component used as the template for the repeated elements.
    Q_PROPERTY(QDeclarativeComponent* delegate READ delegate WRITE setDelegate NOTIFY delegateChanged)
    // "delegate: Label { ... }" then reads as a component assignment (QML engine behaviour).
    Q_CLASSINFO("DefaultProperty", "delegate")

public:
    explicit Repeater(bb::cascades::Container* parent = 0);
    ~Repeater();

    QVariant model() const;
    void setModel(const QVariant& model);

    QDeclarativeComponent* delegate() const;
    void setDelegate(QDeclarativeComponent* delegate);

Q_SIGNALS:
    void modelChanged();
    void delegateChanged();

private:
    void clear();       // remove + delete the previously generated controls
    void regenerate();  // (re)create the controls from the current model + delegate

    QVariant m_model;
    QDeclarativeComponent* m_delegate;
    QList<bb::cascades::Control*> m_controls;
};

} // namespace bbshared

#endif // BBSHARED_REPEATER_HPP
