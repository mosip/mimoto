package io.mosip.mimoto.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.mimoto.util.VersionInfo;

@RestController
public class MimotoServiceController {
    @Autowired
    VersionInfo versionInfo;

    /**
     * Return build properties with git revision and version information.
     *
     * @return
     */
    @GetMapping("/info")
    public ResponseEntity<Object> info() {
        return ResponseEntity.ok().body(versionInfo.getVersionInfo());
    }
}
