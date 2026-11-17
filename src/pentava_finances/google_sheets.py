from googleapiclient.discovery import build

from .google_auth import DEVELOPMENT_USER_ID, require_credentials


def get_google_service(api_name: str, version: str, user_id: str = DEVELOPMENT_USER_ID):
    credentials = require_credentials(user_id)
    return build(
        api_name,
        version,
        credentials=credentials,
        cache_discovery=False,
    )


def list_spreadsheets(
    page_token: str | None = None,
    user_id: str = DEVELOPMENT_USER_ID,
) -> dict:
    service = get_google_service("drive", "v3", user_id)
    return (
        service.files()
        .list(
            q=(
                "mimeType='application/vnd.google-apps.spreadsheet' "
                "and trashed=false"
            ),
            spaces="drive",
            fields="nextPageToken,files(id,name,webViewLink,modifiedTime)",
            orderBy="modifiedTime desc",
            pageSize=100,
            pageToken=page_token,
        )
        .execute()
    )


def get_spreadsheet(spreadsheet_id: str, user_id: str = DEVELOPMENT_USER_ID) -> dict:
    service = get_google_service("sheets", "v4", user_id)
    return (
        service.spreadsheets()
        .get(spreadsheetId=spreadsheet_id)
        .execute()
    )


def get_sheet_values(
    spreadsheet_id: str,
    sheet_range: str,
    user_id: str = DEVELOPMENT_USER_ID,
) -> dict:
    service = get_google_service("sheets", "v4", user_id)
    return (
        service.spreadsheets()
        .values()
        .get(spreadsheetId=spreadsheet_id, range=sheet_range)
        .execute()
    )


TRANSACTION_HEADERS = [
    "Date",
    "Amount",
    "Currency",
    "Type",
    "Category",
    "Description",
    "Reference",
    "Recorded By",
]

# Column widths in pixels for each header above
_COLUMN_WIDTHS = [110, 100, 90, 100, 120, 260, 140, 140]


def create_spreadsheet(
    title: str,
    sheet_name: str = "Transactions",
    user_id: str = DEVELOPMENT_USER_ID,
) -> dict:
    """Create a new spreadsheet pre-formatted with the standard transaction headers."""
    service = get_google_service("sheets", "v4", user_id)

    header_values = [TRANSACTION_HEADERS]

    # Build the spreadsheet with one named sheet and header row in one request
    body = {
        "properties": {"title": title},
        "sheets": [
            {
                "properties": {"title": sheet_name, "index": 0},
                "data": [
                    {
                        "startRow": 0,
                        "startColumn": 0,
                        "rowData": [
                            {
                                "values": [
                                    {
                                        "userEnteredValue": {"stringValue": h},
                                        "userEnteredFormat": {
                                            "textFormat": {"bold": True},
                                            "backgroundColor": {
                                                "red": 0.129,
                                                "green": 0.129,
                                                "blue": 0.129,
                                            },
                                            "foregroundColor": {
                                                "red": 1.0,
                                                "green": 1.0,
                                                "blue": 1.0,
                                            },
                                            "horizontalAlignment": "CENTER",
                                        },
                                    }
                                    for h in TRANSACTION_HEADERS
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }

    spreadsheet = service.spreadsheets().create(body=body, fields="spreadsheetId,spreadsheetUrl,properties,sheets").execute()

    # Freeze header row and set column widths in a followup batchUpdate
    sheet_id = spreadsheet["sheets"][0]["properties"]["sheetId"]
    requests = [
        {
            "updateSheetProperties": {
                "properties": {"sheetId": sheet_id, "gridProperties": {"frozenRowCount": 1}},
                "fields": "gridProperties.frozenRowCount",
            }
        }
    ] + [
        {
            "updateDimensionProperties": {
                "range": {
                    "sheetId": sheet_id,
                    "dimension": "COLUMNS",
                    "startIndex": i,
                    "endIndex": i + 1,
                },
                "properties": {"pixelSize": w},
                "fields": "pixelSize",
            }
        }
        for i, w in enumerate(_COLUMN_WIDTHS)
    ]
    service.spreadsheets().batchUpdate(
        spreadsheetId=spreadsheet["spreadsheetId"],
        body={"requests": requests},
    ).execute()

    return spreadsheet


def append_sheet_row(
    spreadsheet_id: str,
    sheet_range: str,
    values: list[str | int | float | bool | None],
    user_id: str = DEVELOPMENT_USER_ID,
) -> dict:
    service = get_google_service("sheets", "v4", user_id)
    return (
        service.spreadsheets()
        .values()
        .append(
            spreadsheetId=spreadsheet_id,
            range=sheet_range,
            # RAW avoids formula injection in untrusted text fields
            valueInputOption="RAW",
            insertDataOption="INSERT_ROWS",
            body={"values": [values]},
        )
        .execute()
    )
