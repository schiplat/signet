use crate::error::{AppError, AppResult};
use crate::models::User;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Manager,
    Member,
}

impl Role {
    pub fn parse(s: &str) -> AppResult<Self> {
        match s {
            "admin" => Ok(Self::Admin),
            "manager" => Ok(Self::Manager),
            "member" => Ok(Self::Member),
            _ => Err(AppError::bad_request("invalid role")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Manager => "manager",
            Self::Member => "member",
        }
    }
}

impl User {
    pub fn role_enum(&self) -> Role {
        Role::parse(&self.role).unwrap_or(Role::Member)
    }

    pub fn is_admin_role(&self) -> bool {
        self.role_enum() == Role::Admin
    }

    pub fn is_staff(&self) -> bool {
        matches!(self.role_enum(), Role::Admin | Role::Manager)
    }

    pub fn can_manage_users(&self) -> bool {
        self.is_staff()
    }

    pub fn can_delete_users(&self) -> bool {
        self.is_admin_role()
    }

    pub fn can_manage_clients(&self) -> bool {
        self.is_staff()
    }

    pub fn can_delete_clients(&self) -> bool {
        self.is_admin_role()
    }

    /// Manager cannot create/assign admin; cannot modify admins.
    pub fn can_assign_role(&self, target: Role) -> bool {
        match self.role_enum() {
            Role::Admin => true,
            Role::Manager => matches!(target, Role::Manager | Role::Member),
            Role::Member => false,
        }
    }

    pub fn can_mutate_user(&self, target: &User) -> bool {
        self.can_mutate_role(&target.role)
    }

    /// [`Self::can_mutate_user`] for callers that hold only the target's role.
    ///
    /// Split out for the bulk paths, which read the roles of a whole batch in
    /// one query rather than loading a `User` per id.
    pub fn can_mutate_role(&self, target_role: &str) -> bool {
        match self.role_enum() {
            Role::Admin => true,
            Role::Manager => Role::parse(target_role).unwrap_or(Role::Member) != Role::Admin,
            Role::Member => false,
        }
    }
}

pub fn require_staff(user: &User) -> AppResult<()> {
    if user.is_staff() {
        Ok(())
    } else {
        Err(AppError::forbidden("staff required"))
    }
}

pub fn require_admin_role(user: &User) -> AppResult<()> {
    if user.is_admin_role() {
        Ok(())
    } else {
        Err(AppError::forbidden("admin required"))
    }
}
