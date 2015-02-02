{
  "targets": [
    {
      "target_name": "sender",
      "sources": [ "sender.cc"],
      'link_settings': {
          'libraries': [
              '-lnet'
          ]
      }
    }
  ]
}
