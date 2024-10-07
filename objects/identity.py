from stix2 import Identity


def make_emb3d_identity():
    """Creates the default EMB3D identity used for indicating authorship of various components in the bundle.

    Returns:
        identity: a STIX Identity object

    """
    identity = Identity(
        name="EMB3D",
        identity_class="organization",
        description="The EMB3D Threat Model provides a cultivated knowledge base of cyber threats to embedded devices, providing a common understanding of these threats with security mechanisms to mitigate them.",
    )
    return [identity]
