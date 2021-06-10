package com.example.keyclok_demooauth2client;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public ResponseEntity<String> get1() {
        return ResponseEntity.ok("Hello 1");
    }

    @RequestMapping(value = "/anonymous", method = RequestMethod.GET)
    public ResponseEntity<String> get2() {
        return ResponseEntity.ok("Hello 2");
    }

}
