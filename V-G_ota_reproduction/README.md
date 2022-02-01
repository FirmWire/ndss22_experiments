# OTA Reproduction

The subdirectories of this folder contain the patches for replaying our found crashes over the air.
The diffs target slightly different versions than what is reported in the paper, please refer to the table below to find the right version.

| Crash | Radio                 | Stack             |
| ----- | --------------------- | ----------------- |
| CC1   | BladeRF 2.0 micro xA4 | YateBTS 6.2.1     |
| CC2   | BladeRF 2.0 micro xA4 | YateBTS 6.2.1     |
| SM1   | BladeRF 2.0 micro xA4 | Unkown            |
| RRC1  | USRP B210             | OpenLTE v00.20.04 |
| RRC2  | USRP B210             | OpenLTE v00.20.04 |
| RRC3  | USRP B210             | OpenLTE v00.20.04 |

To replicate our experiments, set up the according stack while applying the patch before running it.
In the case of the CC bugs, it may be required to initiate a call to the victim phone.

Unfortunately, we lost the original patches for SM1, as we used this vulnerability only for groundtruth testing early on in the project.
While we plan to replicate our setup and add the patch to the repository later on, please excuse the missing patch file for time being.
