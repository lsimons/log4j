This repo archives some proposed security fixes for Log4j 1.2 that were rejected upstream. It's superceded by [reload4j](https://reload4j.qos.ch/).

# Please see reload4j

[reload4j](https://reload4j.qos.ch/) ([git repo](https://github.com/qos-ch/reload4j)) by the original creator of Log4j 1.2 now has fixes for the same issues as those handled in this repository, and it has official releases. Best to evaluate it instead of this fork if you need a patched fork of Log4j 1.2.

# What security fixes are needed in Log4j 1.2?

Several security vulnerabilities have been identified in Log4J up to and including 1.2.17. Apache advises all users to upgrade to Log4J 2.

For users that cannot upgrade, certain fixes are made available in this repo. You should evaluate them carefully yourself. Please note Log4J 1 remains End Of Life. These are unofficial, unmaintained, and unsupported patches.

## Changes

Besides many build system and packaging changes, the important changes in this repository are:

* [fix: remove insecure code from log4j.net package](https://github.com/lsimons/log4j/tree/fix/2021-secure-net)
  * fixes [CVE-2019-17571](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17571)
  * warns against [CVE-2020-9488](https://nvd.nist.gov/vuln/detail/CVE-2020-9488)
  * fixes [CVE-2021-4104](https://nvd.nist.gov/vuln/detail/CVE-2021-4104)
* [fix: remove insecure code from log4j.jmx package](https://github.com/lsimons/log4j/tree/fix/2021-secure-jmx)
  * no CVE, disable networking code
* [fix: remove insecure code from jdbc package](https://github.com/lsimons/log4j/tree/fix/2021-secure-jdbc)
  * no CVE, avoids possible SQL injection
* [fix: remove insecure code from varia package](https://github.com/lsimons/log4j/tree/fix/2021-secure-erfa)
  * no CVE, disables networking code
* [fix: allow MDC to work on Java >= 9](https://github.com/lsimons/log4j/tree/fix/2021-mdc-java-version) 
  * forward compatibility with recent java versions, not security related

## Using these fixes

You should consider carefully whether to these fixes in your software. Having maintainers for your software dependencies matters, and Log4j 1.2 remains unmaintained.

More importantly, when dealing with security in old legacy systems you really should not download binaries from random github accounts. That's why there is no release available of this fork and one will not be made available.

If you do wish to use these patches, first audit the code changes and then make your own internal release. See [INSTALL](./INSTALL) for build instructions.

Most likely the process of auditing the source code will convince you that log4j 1.2 is really really old, and to either try and upgrade to Log4j 2 or logback, or to secure your Log4j 1 setup some other way. If not, best of luck!

# Why not fork Log4j 1.2 into a new project?

First, cost. The history described below hopefully gives _some_ clues about the tremendous cost to the java ecosystem of having multiple competing partially-compatible logging implementations. The cost of this competition is much higher than the added value: after all this is _just a logging library_. Having another competitor around is _really_ not worth it in the long run.

Second, quality. Log4j 1.2 is very old software and by modern java standards its source code is quite low quality. It does not deserve the wide use that it has and everyone should _really_ stop using it.

Third, effort. Supporting an open source library is a significant amount of work. If you are in need that support, find someone you can pay to provide it to you.

# A history of java logging

So as to perhaps convince you not to fork :-).

## Java logging 1999-2009: log4j dominance

Log4j was created in December 1999 and became an Apache project in early 2000. It quickly become the most-used open source logging library. Since java had very little support built-in for logging, this made log4j one of the most-used libraries in java software everywhere.

Java 1.4 was released in February 2002 and included a basic facility for logging, java.util.logging. Unfortunately this library had bad ergonomics and low performance compared to existing open source libraries such as log4j.

Because having multiple different logging libraries in use in one program is annoying, many libraries and frameworks started using an abstraction layer, to give developers a choice between log4j, java.util.logging, and others. For a long while the most common abstraction layer was [commons-logging](https://commons.apache.org/proper/commons-logging/), eventually getting competition from the technically superior [slf4j](https://www.slf4j.org/).

In early 2005, developers of various logging libraries within the apache community had a series of disagreements about the way forward. At the time Apache was home to log4j, commons-logging, JULI (the logging facility in apache tomcat), and logkit. After these disagreements, the original creator of log4j left Apache to create the competing projects [slf4j](https://www.slf4j.org/) and [logback](https://logback.qos.ch/).

After 2005, the remaining developers of log4j at Apache abandoned the in-development 1.3 branch. Log4j 1.2 version slowly switched to a mostly maintenance mode.

From 2006 onward, slf4j and to a lesser degree logback started gaining popularity, because they were technically superior to commons-logging and log4j 1.2, and probably also because their author did a lot of promotion for them. For example, the popular Spring Framework used to dedicate relatively a lot of documentation to [how to use it with slf4j](https://docs.spring.io/spring-framework/docs/3.2.9.RELEASE/spring-framework-reference/html/overview.html#overview-logging) even though commons-logging was its default!

## Java logging 2009-2019: adoption of SLF4J

In 2010 the Apache log4j community started a completely new logging implementation from scratch, Log4j 2, with some backward compatibility for Log4j 1.x but a very different design, competing with logback in terms of feature set and performance.

On May 26, 2012, the last official release of Log4j 1.2 was made, version 1.2.17.

On July 13, 2014, Apache released Log4j 2.0, and soon after started advising all 1.2 users to upgrade. Later versions improved compatibility with Log4j 1.2 somewhat.

On August 5, 2015, Apache announced that Log4j 1.x had officially reached end of life, 3 years after its last maintenance release.

From 2015 onwards, most new open source projects would default to either Logback or Log4j 2, using either commons-logging or slf4j as their abstraction layer. For example, Spring Boot 1.0.0 released in April 2014, [providing logback as the default, supporting other logging libraries if needed](https://docs.spring.io/spring-boot/docs/1.0.0.RELEASE/reference/html/boot-features-logging.html).

## Java logging after 2019: security issues

In December 2019, a _major_ security vulnerability [CVE-2019-17571](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17571) was reported against Log4j 1.2, with users advised to upgrade to 2.0.

Several important open source projects only upgraded their log4j dependency after this vulnerability was reported. Other projects found the vulnerability did not apply for them and they are still happily using 1.2.17. For example, in Apache Kafka the relevant fix [KAFKA-9366](https://github.com/apache/kafka/pull/7898) remains unmerged after several years.

In December 2021, Apache Log4j 2.x became quite famous due to a couple of **severe** [security vulnerabilities](https://logging.apache.org/log4j/2.x/) together dubbed "log4shell". The java community and the wider internet community found itself auditing and evaluating all its uses of log4j. Most users of log4j 2.x chose to upgrade to a patched version, while some chose to switch to SLF4J, logback, or java.util.logging.

Not just Log4j got subjected to scrutiny, a medium (so _much_ less serious) security vulnerability [CVE-2021-42550](https://nvd.nist.gov/vuln/detail/CVE-2021-42550) was reported in December 2021 against Logback, too, and quickly fixed.

## Log4j 1.2 remains End-Of-Life

Existing usage of Log4j 1.2 of course also came under increased scrutiny, as security auditors keyword-matched their way to increased awareness of CVE-2019-17571, and maintainers started looking for fixes.

This repository contains backwards-compatible fixes for Log4j 1.2.17 to fix the security vulnerabilities reported against it. Going further than the reported vulnerabilities, it disables some potentially unsafe code that isn't part of a CVE-reported vulnerability. It was proposed (PR [#16](https://github.com/apache/logging-log4j1/pull/16), [#17](https://github.com/apache/logging-log4j1/pull/17)) to the Apache Log4j team as basis for a security release as Log4j 1.2.18. The community discussed possibilities for such a release at length and reviewed several possible technical and communication approaches.

On January 6, 2022, after significant deliberation and a vote, the Apache Log4J team decided not to produce a new security release for Log4j, see the [logging-log4j1 readme](https://github.com/apache/logging-log4j1/blob/main/README.md). The proposed security fixes in this repository will not be accepted or released by Apache.

On January 12, 2022, the original author of Log4j 1.2 released Reload4j, a security-fix only fork of Log4j 1.2. It contains similar fixes to this repository and is supported by its author who also takes donations/sponsorship to do so sustaintably.
