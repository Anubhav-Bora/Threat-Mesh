from sqlalchemy import insert, select
from sqlalchemy.dialects import postgresql

from app.models import IOC


def test_postgis_values_are_bound_and_selected_as_text() -> None:
    insert_sql = str(
        insert(IOC)
        .values(location="SRID=4326;POINT(8.6821 50.1109)")
        .compile(dialect=postgresql.dialect())
    )
    select_sql = str(select(IOC.location).compile(dialect=postgresql.dialect()))
    assert "ST_GeogFromText" in insert_sql
    assert "ST_AsEWKT" in select_sql
