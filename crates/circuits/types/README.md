# Input Types for circuits

A separated crate for the input types accepted by circuits as input.

This crate help decoupling circuits with other crates and keep their dependencies neat and controllable. Avoiding to involve crates which is not compatible with the tootlchain of openvm from indirect dependency.

It also provide utilities to generate test data files which can be used by openvm's cli.