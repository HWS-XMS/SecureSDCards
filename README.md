# Secure SD Cards

Open-source hardware and software for the paper
**"Secure SD Cards: A Threat Model and Security Analysis"** (HASP 2026, co-located with MICRO).

The platform interacts with secure SD cards offline, recovers their vendor
protocols, and mounts side-channel and fault-injection attacks for under $350.

## Layout

```
hardware/
  sd-interposer/      SD-form-factor bus-tap interposer (KiCad)
  greatfet-neighbor/  GreatFET add-on board: power control and shunt (KiCad)
firmware/
  greatfet-sdio/      SD/SDIO host class for the GreatFET firmware
software/
  greatfet/           GreatFET-based SD host (Python API)
  swissbit_lib/       Swissbit PS-66u / FSI protocol library and decoder
  flexxon_lib/        Flexxon X-Mask protocol library and encoder
  decoder/            Saleae Logic 2 parser for X-Mask captures
docs/
  protocols/          Recovered vendor protocol documentation
```

The EMFI tool is released separately as
[ShoutDUINO](https://github.com/HWS-XMS/ShoutDUINO).

## Dependencies

```
pip install -r requirements.txt
```

The GreatFET host also requires the GreatFET firmware and tools
(https://github.com/greatscottgadgets/greatfet).

## License

MIT. See [LICENSE](LICENSE).
