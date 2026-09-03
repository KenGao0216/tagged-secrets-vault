package io.github.kengao0216.vault.domain;

/**
 * What a principal is allowed to do. Deliberately a closed set, new roles require a code change and a review
 */
public enum Role {
    ADMIN, //Full access
    SERVICE_READER, //Reads only the secrets its own service is scoped to
    AUDITOR; //reads the audit log

    public boolean canReadSecretValues(){
        return switch (this){
            case ADMIN -> true;
            case SERVICE_READER -> true;
            case AUDITOR -> false;
        };
    }

    public boolean canReadAuditLog(){
        return switch (this){
            case ADMIN -> true;
            case SERVICE_READER -> false;
            case AUDITOR -> true;
        };
    }
    // Note: no tag-scoping logic belongs here. Deciding which secrets a SERVICE_READER
    // may see depends on the caller's identity, not just its role, will be in `auth`, at query-construction time.
}
