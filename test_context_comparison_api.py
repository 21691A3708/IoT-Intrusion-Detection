def near(a, b):

    return math.isclose(
        a,
        b,
        rel_tol=0,
        abs_tol=TOLERANCE,
    )