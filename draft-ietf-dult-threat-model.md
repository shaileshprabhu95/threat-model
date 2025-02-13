---
title: "DULT Threat Model"
category: info

docname: draft-ietf-dult-threat-model-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Detecting Unwanted Location Trackers"
keyword:
 - Internet-Draft
 - detecting unwanted location trackers
 - threat model
venue:
  group: "Detecting Unwanted Location Trackers"
  type: "Working Group"
  mail: "unwanted-trackers@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/unwanted-trackers/"
  github: "ietf-wg-dult/draft-ietf-dult-threat-model"
  latest: "https://ietf-wg-dult.github.io/threat-model/draft-ietf-dult-threat-model.html"

author:
 -
    fullname: "Maggie Delano"
    organization: Swarthmore College
    email: "mdelano1@swarthmore.edu"

 -
    fullname: "Jessie Lowell"
    organization: National Network to End Domestic Violence
    email: jlowell@nnedv.org

normative:

informative:


--- abstract

Lightweight location tracking tags are in wide use to allow users to locate items. These tags function as a component of a crowdsourced tracking network in which devices belonging to other network users (e.g., phones) report which tags they see and their location, thus allowing the owner of the tag to determine where their tag was most recently seen. While there are many legitimate uses of these tags, they are also susceptible to misuse for the purpose of stalking and abuse. A protocol that allows others to detect unwanted location trackers must incorporate an understanding of the unwanted tracking landscape today. This document provides a threat analysis for this purpose, will define what is in and out of scope for the unwanted location tracking protocols, and will provide some design considerations for implementation of protocols to detect unwanted location tracking.

--- middle

# Introduction

Location tracking tags are widely-used devices that allow users to locate items. These tags function as a component of a crowdsourced tracking network in which devices belonging to other network users (e.g., phones) report on the location of tags they have seen. At a high level, this works as follows:

  - Tags ("accessories") broadcast an advertisement payload containing accessory-specific information. The payload also indicates whether the accessory is separated from its owner and thus potentially lost.
  - Devices belonging to other users ("non-owner devices") observe those payloads and if the payload is in a separated mode, reports its location to some central service.
  - The owner queries the central service for the location of their accessory.

A naive implementation of this design exposes both a tag’s user and anyone who might be targeted for location tracking by a tag’s user, to considerable privacy risk. In particular:

  - If accessories simply have a fixed identifier that is reported back to the tracking network, then the central server is able to track any accessory without the user's assistance, which is clearly undesirable.
  - Any attacker who can guess a tag ID can query the central server for its location.
  - An attacker can surreptitiously plant an accessory on a target and thus track them by tracking their "own" accessory.

In order to minimize these privacy risks, it is necessary to analyze and be able to model different privacy threats. This document uses a flexible framework to provide analysis and modeling of different threat actors, as well as models of potential victims based on their threat context. It defines how these attacker and victim persona models can be combined into threat models. It is intended to work in concert with the requirements defined in {{!I-D.detecting-unwanted-location-trackers}}, which facilitate detection of unwanted tracking tags.

# Conventions and Definitions

## Conventions
{::boilerplate bcp14-tagged}

## Definitions

- **active scanning**: a search for location trackers manually initiated by a user
- **passive scanning**: a search for location trackers running in the background, often accompanied by notifications for the user
- **tracking tag**: a small, concealable device that broadcasts location data to other devices

# Security Considerations

Incorporation of this threat analysis into the DULT protocol does not introduce any security risks not already inherent in the underlying Bluetooth tracking tag protocols. Existing attempts to prevent unwanted tracking by the owner of a tag have been criticized as potentially making it easier to engage in unwanted tracking of the owner of a tag. However, Beck et al. have [demonstrated](https://eprint.iacr.org/2023/1332.pdf) a technological solution that employs secret sharing and error correction coding.

## Taxonomy of unwanted tracking

To create a taxonomy of threat actors, we can borrow from Dev et al.’s [Models of Applied Privacy (MAP) framework](https://dl.acm.org/doi/fullHtml/10.1145/3544548.3581484). This framework is intended for organizations and includes organizational threats and taxonomies of potential privacy harms. Therefore, it cannot be applied wholesale. However, its flexibility, general approach to personas, and other elements, are applicable or can be modified to fit the DULT context.

The characteristics of threat actors may be described as follows. This is not intended to be a full and definitive taxonomy, but an example of how existing persona modeling concepts can be applied and modified.

  - Expertise level
    - Expert: The attacker works in or is actively studying computer science, networking, computer applications, IT, or another technical field.
    - Non-expert: The attacker does not work or study in, or is a novice in, a technical field.
  - Proximity to victim
    - High: Lives with victim or has easy physical access to victim and/or victim’s possessions.
    - Medium: Has some physical access to the person and possessions of someone who lives with victim, such as when the attacker and victim are co-parenting a child.
    - Low: Does not live with or have physical access to victim and/or victim’s possessions.
  - Access to resources
    - High: The attacker has access to resources that may amplify the impact of other characteristics. These could include, but are not limited to, funds (or control over “shared” funds), persons assisting them in stalking behavior, or employment that provides privileged access to technology or individuals’ personal information.
    - Low: The attacker has access to few or no such resources.

In addition, the victim also has characteristics which influence the threat analysis. As with attacker characteristics, these are not intended as a definitive taxonomy.

  - Expertise level
    - Expert: The victim works in or is actively studying computer science, networking, computer applications, IT, or another technical field.
    - Non-expert: The victim does not work or study in, or is a novice in, a technical field.
  - Access to resources
    - High: The victim is generally able to safely access practical and relevant resources. These might include funds to pay a car mechanic or private investigator, law enforcement or legal assistance, or other resources.
    - Low: The victim is generally unable to safely access practical and relevant resources. These might include money to pay a car mechanic or private investigator, law enforcement or legal assistance, or other resources.
  - Access to technological safeguards
    - High: The victim is able to safely use, and has access to, technological safeguards such as active scanning apps.
    - Limited: The victim is able to safely use, and has access to, technological safeguards such as active scanning apps, but is unable to use their full capacity.
    - Low: The victim is not able to use technological safeguards such as active scanning apps, due to reasons of safety or access.

It is also appropriate to define who is using the tracking tags and incorporate this into a model. This is because if protocols overly deprioritize the privacy of tracking tags’ users, an attacker could use a victim’s own tag to track them. Beck et al. describe a [possible technological solution](https://eprint.iacr.org/2023/1332.pdf) to the problem of user privacy vs privacy of other potential victims.

  - Tracking tag usage
    - Attacker only: The attacker controls one or more tracking tags, but the victim does not.
    - Victim only: The victim controls one or more tracking tags, but the attacker does not.
    - Attacker and victim: Both the attacker and victim control one or more tracking tags.

### Example scenarios with analyses

The following scenarios are composite cases based upon reports from the field. They are intended to illustrate different angles of the problem. They are not only technological, but meant to provide realistic insights into the constraints of people being targeted through these tags. There is no identifying information for any real person contained within them. In accordance with research on [how designers understand personas](https://dl.acm.org/doi/10.1145/2207676.2208573), the characters are given non-human names without attributes such as gender or race.
The analysis of each scenario provides an example usage of the modeling framework described above. It includes a tracking tag usage element for illustrative purposes. However, as discussed previously, this element becomes more or less relevant depending on protocol evolution.
Note that once a given attacker persona has been modeled, it could be recombined with a different victim persona, or vice versa, to model a different scenario. For example, a non-expert victim persona could be combined with both non-expert and expert attacker personas.

#### Scenario 1

##### Narrative

Mango and Avocado have two young children. Mango, Avocado, and the children all use smartphones, but have no specialized technical knowledge. Mango left because Avocado was abusive. They were homeless for a month, and the children have been living with Avocado. They now have an apartment two towns away. They do not want Avocado to know where it is, but they do want to see the children. They and Avocado meet at a public playground. They get there early so that Avocado will not see which bus route they arrived on and keep playing with the children on the playground until after Avocado leaves, so that Avocado will not see which bus route they get on. Two days later, Avocado shows up at Mango’s door, pounding on the door and shouting.

##### Analysis

In this case, the attacker has planted a tag on a child. Co-parenting after separation is common in cases of intimate partner violence where the former partners have a child together. Child visits can be an opportunity to introduce technology for purposes of stalking the victim.

| Attacker Profile | Avocado |
| ------------- | ------------- |
| Expertise Level  | Non-Expert  |
| Proximity to Victim  | Medium  |
| Access to Resources  | Unknown, but can be presumed higher than Mango’s due to Mango’s recent homelessness  |

|Victim Profile | Mango |
| ------------- | ------------- |
| Expertise Level  | Non-Expert  |
| Access to Resources  | Low  |
| Access to Technological Safeguards  | Normal  |

|Other Characteristics | Avocado and Mango |
| ------------- | ------------- |
| Accessory Usage  | Attacker Only  |

#### Scenario 2

##### Narrative

Strawberry and Elderberry live together. Neither has any specialized technological knowledge. Strawberry has noticed that Elderberry has become excessively jealous – every time they go to visit a friend by themselves, Elderberry accuses them of infidelity. To their alarm, over the last week, on multiple occasions, Elderberry has somehow known which friend they visited at any given time and has started to harass the friends. Strawberry eventually gets a notification that a tracker is traveling with them, and thinks it may be in their car, but they cannot find it. They live in a car-dependent area and cannot visit friends without the car, and Elderberry controls all of the “family” money, so their cannot take the car to the mechanic without Elderberry knowing.

##### Analysis

Here, the attacker and the victim are still cohabiting, and the attacker is monitoring the victim’s independent activities. This would allow the attacker to know if, for instance, the victim went to a police station or a domestic violence agency. The victim has reason to think that they are being tracked, but they cannot find the device. This can happen if the sound emitted by the device is insufficiently loud, and is particularly a risk in a car, where seat cushions or other typical features of a car may provide sound insulation for a hidden tag. The victim could benefit from having a mechanism to increase the volume of the sound emitted by the tag. Another notable feature of this scenario is that because of the cohabitation, the tag will spend most of the time in “near-owner state” as defined by the proposed industry consortium specification {{I-D.detecting-unwanted-location-trackers}}. In near-owner state it would not provide alerts under that specification.

| Attacker Profile | Elderberry |
| ------------- | ------------- |
| Expertise Level  | Non-Expert  |
| Proximity to Victim  | High  |
| Access to Resources  | High  |

|Victim Profile | Strawberry |
| ------------- | ------------- |
| Expertise Level  | Non-Expert  |
| Access to Resources  | Low  |
| Access to Technological Safeguards  | Impaired (cannot hear alert sound)  |

|Other Characteristics | Elderberry and Strawberry |
| ------------- | ------------- |
| Accessory Usage  | Attacker Only  |

#### Scenario 3

##### Narrative

Lime and Lemon have been dating for two years. Lemon works for a tech company and often emphasizes how much more they know about technology than Lime, who works at a restaurant. Lemon insists on having access to Lime’s computer and Android phone so that they can “make sure they are working well and that there are no dangerous apps.” Lemon hits Lime when angry and has threatened to out Lime as gay to their conservative parents and report them to Immigration & Customs Enforcement if Lime “talks back.” Lime met with an advocate at a local domestic violence program to talk about going to their shelter once a bed was available. The advocate did some safety planning with Lime, and mentioned that there is an app for Android that can scan for location trackers, but Lime did not feel safe installing this app because Lemon would see it. The next time Lime went to see the advocate, they chose a time when they knew Lemon had to be at work until late to make sure that Lemon did not follow them, but when Lemon got home from work they knew where Lime had been.

##### Analysis

This is a case involving a high-skill attacker, with a large skill difference between attacker and victim. This situation often arises in regions with a high concentration of technology industry workers. It also may be more common in ethnic-cultural communities with high representation in the technology industry. In this case the victim is also subject to a very high level of control from the attacker due to their imbalances in technological skills and societal status, and is heavily constrained in their options as a result. It is unsafe for the victim to engage in active scanning, or to receive alerts on their phone. The victim might benefit from being able to log into an account on another phone or a computer and view logs of any recent alerts collected through passive scanning.

| Attacker Profile | Lemon |
| ------------- | ------------- |
| Expertise Level  | Expert  |
| Proximity to Victim  | High  |
| Access to Resources  | High  |

|Victim Profile | Lime |
| ------------- | ------------- |
| Expertise Level  | Non-Expert  |
| Access to Resources  | Low  |
| Access to Technological Safeguards  | Low  |

|Other Characteristics | Lemon and Lime |
| ------------- | ------------- |
| Accessory Usage  | Attacker Only  |

### Bluetooth vs. other technologies

The above taxonomy and threat analysis focus on location tracking tags. They are protocol-independent; if a tag were designed using a technology other than Bluetooth, they would still apply. The key attributes are the functionalities and physical properties of the accessory from the user’s perspective. The accessory must be small enough to be easily concealed, and able to broadcast its location to other consumer devices.

## What is in scope

### Technologies

The scope of this threat analysis includes any easily-concealable accessory that is able to broadcast its location to other consumer devices.

### Attacker Profiles

An attacker who attempts to track a victim using a tracking tag and applications readily available for end-users (e.g. native tracking application) is in scope. Additonally, an attacker who physically modifies a tracking tag (e.g. to disable a speaker) is in scope. An atacker who makes non-nation-state level alterations to the firmware of an existing tracking tag or creates a custom device that leverages the crowdsourced tracking network is in scope.

### Victim Profiles

All victims profiles are in scope regardless of their expertise, access to resources, or access to technological safeguards. For example, protocols should account for a victim's lack of access to a smartphone, and scenarios in which victims cannot install separate software.

## What is out of scope

### Technologies

There are many types of technology that can be used for location tracking. In many cases, the threat analysis would be similar, as the contexts in which potential attackers and victims exist and use the technology are similar. However, it would be infeasible to attempt to describe a threat analysis for each possible technology in this document. We have therefore limited its scope to location-tracking accessories that are small enough to be easily concealed, and able to broadcast their locations to other devices. The following are out of scope for this document:

  - App-based technologies such as parental monitoring apps.
  - Other Internet of Things (IoT) devices.
  - Connected cars.
  - User accounts for cloud services or social media.

### Attack Profiles

Attackers with nation-state level expertise and resources who deploy custom or altered tracking tags to bypass protocol safeguards or jailbreak a victim end-device (e.g. smartphone) are considered out of scope.

### Victim Profiles

N/A


# Design Considerations

As discussed in {{security-considerations}}, unwanted location tracking can involve a variety of attacker, victim, and tracking tag profiles. A successful implementation to preventing unwanted location tracking should:

- Include a variety of approaches to address different scenarios, including active and passive scanning and notifications or sounds
- Account for scenarios in which the attacker has high expertise, proximity, and/or access to resources within the scope defined in {{what-is-in-scope}} and {{what-is-out-of-scope}}
- Account for scenarios in which the victim has low expertise, access to resources, and/or access to technological safeguards within the scope defined in {{what-is-in-scope}} and {{what-is-out-of-scope}}
- Avoid privacy compromises for the tag owner when protecting against unwanted location tracking using tracking tags

## Design Requirements

The DULT protocol should 1) allow victims to detect unwanted location tracking, 2) help victims find tags that are tracking them, and 3) provide instructions for victims to disable those trackers if they choose. These affordances should be implemented while considering the appropriate privacy and security requirements.

### Detecting Unwanted Location Tracking

There are three main ways that the DULT protocol should assist victims in detecting potentially unwanted location tracking: 1) active scanning, 2) passive scanning, and 3) tracking tag alerts.

#### Active Scanning

There may be scenarios where a victim suspects that they are being tracked without their consent. Active scanning should allow a user to use a native application on their device to search for tracking tags that are separated from their owners. Additional information about when that tag has been previously encountered within a designated time window (e.g. the last 12 hours) should also be included if available (see {{privacy-and-security-requirements-todo}}). Allowing users to "snooze" or ignore tags known to be safe (e.g. tags from a family member) could also be implemented. Tracking tags that are near their owners should not be shared to avoid abuse of the active scanning feature.

#### Passive Scanning

The platform should passively scan for devices suspected of unwanted location tracking and notify the user. This will involve implementing one or more algorithms to use to flag trackers and determine when to notify the user. (A dedicated DULT WG document will address tracking algorithms, and will be linked when it is available.) The user could be notified through a push notification or through Sounds and Haptics (see {{tracking-tag-alerts}}). There will be tradeoffs between detecting potential unwanted location tracking promptly and alerting the potential victim prematurely. One way to handle these tradeoffs is to allow users to set the sensitivity of these alerts. For example, the [AirGuard](https://github.com/seemoo-lab/AirGuard) app includes three different "Security Level" settings that users can customize.

#### Tracking Tag Alerts

Tracking tags may be difficult to locate, and users may not have a device that can actively or passively scan for tracking tags. The DULT protocol should be built with [accessibility in mind](https://cdt.org/insights/centering-disability-in-mitigating-harms-of-bluetooth-tracking-technology/) so that the most people can be protected by the protocol. In addition to push notifications on nearby devices, tracking tags themselves should be able to notify end users. This should include periodic sounds when away from an owner, along with lights and haptics so that people who are Deaf or hard of hearing can still locate them.

### Finding Tracking Tags (JESSIE TODO)

### Disabling Tracking Tags (JESSIE TODO)

### Privacy and Security Requirements (TODO)


## Design Constraints

There are also design constraints that the DULT Protocol must consider, including limitations of the Bluetooth Low Energy (BLE) protocol, power constraints, and device constraints.

### Bluetooth constraints

The Bluetooth Low Energy (BLE) payload used for advertisement consists of up to 37 bytes. One current adoption of unwanted location tracking requires 12 of these bytes for implementing the basic protocol, with the remaining optional (see {{!I-D.detecting-unwanted-location-trackers}}). Implementation of the DULT protocol will need to consider these limitations. For example, in [Eldridge et al](https://eprint.iacr.org/2023/1332.pdf), implementing Multi-Dealer Secret Sharing required using two advertisement packets were needed instead of one.

### Power constraints (TODO)

### Device constraints (TODO)

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
