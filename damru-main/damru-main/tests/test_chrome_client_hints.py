from damru.devices import pick_random_chrome_version


def test_chrome_145_client_hints_match_android_native_order():
    chrome_ver, brand_info = pick_random_chrome_version(force_version="145.0.7632.75")

    assert chrome_ver == "145.0.7632.75"
    assert brand_info["brands"] == [
        {"brand": "Not:A-Brand", "version": "99"},
        {"brand": "Google Chrome", "version": "145"},
        {"brand": "Chromium", "version": "145"},
    ]
    assert brand_info["fullVersionList"] == [
        {"brand": "Not:A-Brand", "version": "99.0.0.0"},
        {"brand": "Google Chrome", "version": "145.0.7632.75"},
        {"brand": "Chromium", "version": "145.0.7632.75"},
    ]

