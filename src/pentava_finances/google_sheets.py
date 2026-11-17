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
