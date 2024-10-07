from stix2 import CustomObject, properties, ExternalReference


valid_tactics = [
    "hardware",
    "system-software",
    "application-software",
    "networking",
]


@CustomObject(
    "x-mitre-tactic",
    [
        ("name", properties.StringProperty(required=True)),
        ("description", properties.StringProperty(required=True)),
        ("x_mitre_shortname", properties.StringProperty(required=True)),
        ("external_references", properties.ListProperty(ExternalReference)),
    ],
)
class Tactic(object):
    def __init__(self, x_mitre_shortname=None, **kwargs):
        if x_mitre_shortname and x_mitre_shortname not in valid_tactics:
            raise ValueError(f"'{x_mitre_shortname}' is not a recognized EMB3D Tactic.")


def make_emb3d_tactics(identity_id):
    """Create all EMB3D tactic objects.

    Args:
        data: The tactic names list.

    Returns:
        A list of Tactics.

    """
    tactics = []
    for t in valid_tactics:
        external_references = [
            {
                "external_id": t,
                "source_name": "EMB3D",
                "url": f"https://emb3d.mitre.org/threats/{t}.html",
            }
        ]

        tactic = Tactic(
            name=t,
            description=t.capitalize(),
            x_mitre_shortname=t.lower().replace(" ", "-"),
            external_references=external_references,
            created_by_ref=identity_id,
        )

        tactics.append(tactic)

    return tactics
