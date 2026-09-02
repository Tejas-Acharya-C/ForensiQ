import os
import sys
from app.database.session import SessionLocal
from app.models.investigation import Investigation
from app.models.user import User
import uuid

def main():
    db = SessionLocal()
    try:
        user = db.query(User).first()
        if not user:
            from app.core.security import hash_password
            user = User(
                id=uuid.uuid4(),
                email="dev@forensiq.test",
                password_hash=hash_password("Dev123!@#"),
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print("Created a new dev user.")

        inv = Investigation(
            title="Test Investigation",
            description="Testing the reset functionality",
            case_number=f"TEST-{uuid.uuid4().hex[:6].upper()}",
            owner_user_id=user.id
        )
        db.add(inv)
        db.commit()
        print(f"Created investigation: {inv.case_number}")
        
        count = db.query(Investigation).count()
        print(f"Total investigations in DB: {count}")

    finally:
        db.close()

if __name__ == "__main__":
    main()
