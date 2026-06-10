package me.charlie.sinsprotocol.server;

@FunctionalInterface
public interface SensorReadingProvider {

    String nextReading();
}
