Welcome to _Bitcoin Wallet_, a standalone Bitcoin payment app for your Android device!

This project contains several sub-projects:

 * __wallet__:
     The Android app itself. This is probably what you're searching for.
 * __market__:
     App description and promo material for the Google Play app store.
 * __integration-android__:
     A tiny library for integrating Bitcoin payments into your own Android app
     (e.g. donations, in-app purchases).
 * __sample-integration-android__:
     A minimal example app to demonstrate integration of Bitcoin payments into
     your Android app.

You can build all sub-projects at once using Maven:

`mvn clean install`

Or go into the wallet directory and run the following using Maven:

`mvn clean install -Dandroid.sdk.path=<path_to_android_sdk> -DskipTests`

