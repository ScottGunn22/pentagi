import { useMemo, useState } from 'react';

import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import {
    type FindingFragmentFragment,
    SeverityLevel,
    VerificationStatus,
} from '@/graphql/types';

const severityRank: Record<SeverityLevel, number> = {
    [SeverityLevel.Critical]: 5,
    [SeverityLevel.High]: 4,
    [SeverityLevel.Info]: 1,
    [SeverityLevel.Low]: 2,
    [SeverityLevel.Medium]: 3,
};

const severityLabel: Record<SeverityLevel, string> = {
    [SeverityLevel.Critical]: 'Critical',
    [SeverityLevel.High]: 'High',
    [SeverityLevel.Info]: 'Info',
    [SeverityLevel.Low]: 'Low',
    [SeverityLevel.Medium]: 'Medium',
};

const severityClass: Record<SeverityLevel, string> = {
    [SeverityLevel.Critical]: 'bg-red-600 text-white',
    [SeverityLevel.High]: 'bg-orange-500 text-white',
    [SeverityLevel.Info]: 'bg-muted text-muted-foreground',
    [SeverityLevel.Low]: 'bg-blue-500 text-white',
    [SeverityLevel.Medium]: 'bg-yellow-500 text-black',
};

const verificationLabel: Record<VerificationStatus, string> = {
    [VerificationStatus.Confirmed]: 'Confirmed',
    [VerificationStatus.FalsePositive]: 'False positive',
    [VerificationStatus.NotExploitable]: 'Not exploitable',
    [VerificationStatus.Unverified]: 'Unverified',
    [VerificationStatus.Verifying]: 'Verifying',
};

interface FindingsTableProps {
    findings: FindingFragmentFragment[];
}

type ScopeFilter = 'all' | 'in' | 'out';
type SeverityFilter = 'all' | SeverityLevel;
type VerificationFilter = 'all' | VerificationStatus;

export function FindingsTable({ findings }: FindingsTableProps) {
    const [search, setSearch] = useState('');
    const [severity, setSeverity] = useState<SeverityFilter>('all');
    const [verification, setVerification] = useState<VerificationFilter>('all');
    const [scope, setScope] = useState<ScopeFilter>('all');

    const filtered = useMemo(() => {
        const q = search.trim().toLowerCase();

        return findings
            .filter((finding) => {
                if (severity !== 'all' && finding.severity !== severity) {
                    return false;
                }

                if (verification !== 'all' && finding.verificationStatus !== verification) {
                    return false;
                }

                if (scope === 'in' && !finding.inScope) {
                    return false;
                }

                if (scope === 'out' && finding.inScope) {
                    return false;
                }

                if (q) {
                    const haystack = [
                        finding.title,
                        finding.cve ?? '',
                        finding.target.ref,
                    ]
                        .join(' ')
                        .toLowerCase();

                    if (!haystack.includes(q)) {
                        return false;
                    }
                }

                return true;
            })
            .sort((a, b) => {
                const rankDiff = severityRank[b.severity] - severityRank[a.severity];

                if (rankDiff !== 0) {
                    return rankDiff;
                }

                return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
            });
    }, [findings, scope, search, severity, verification]);

    return (
        <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
                <Input
                    className="w-64"
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search title, CVE, or target"
                    value={search}
                />
                <Select
                    onValueChange={(value) => setSeverity(value as SeverityFilter)}
                    value={severity}
                >
                    <SelectTrigger className="w-40">
                        <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All severities</SelectItem>
                        <SelectItem value={SeverityLevel.Critical}>Critical</SelectItem>
                        <SelectItem value={SeverityLevel.High}>High</SelectItem>
                        <SelectItem value={SeverityLevel.Medium}>Medium</SelectItem>
                        <SelectItem value={SeverityLevel.Low}>Low</SelectItem>
                        <SelectItem value={SeverityLevel.Info}>Info</SelectItem>
                    </SelectContent>
                </Select>
                <Select
                    onValueChange={(value) => setVerification(value as VerificationFilter)}
                    value={verification}
                >
                    <SelectTrigger className="w-48">
                        <SelectValue placeholder="Verification" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All verifications</SelectItem>
                        <SelectItem value={VerificationStatus.Unverified}>Unverified</SelectItem>
                        <SelectItem value={VerificationStatus.Verifying}>Verifying</SelectItem>
                        <SelectItem value={VerificationStatus.Confirmed}>Confirmed</SelectItem>
                        <SelectItem value={VerificationStatus.FalsePositive}>False positive</SelectItem>
                        <SelectItem value={VerificationStatus.NotExploitable}>Not exploitable</SelectItem>
                    </SelectContent>
                </Select>
                <Select
                    onValueChange={(value) => setScope(value as ScopeFilter)}
                    value={scope}
                >
                    <SelectTrigger className="w-40">
                        <SelectValue placeholder="Scope" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All findings</SelectItem>
                        <SelectItem value="in">In scope</SelectItem>
                        <SelectItem value="out">Out of scope</SelectItem>
                    </SelectContent>
                </Select>
                <span className="text-muted-foreground ml-auto text-xs">
                    {filtered.length} of {findings.length} finding{findings.length === 1 ? '' : 's'}
                </span>
            </div>

            {filtered.length === 0 ? (
                <div className="text-muted-foreground rounded-md border border-dashed p-6 text-center text-sm">
                    No findings match the current filters.
                </div>
            ) : (
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead>Severity</TableHead>
                            <TableHead>Title</TableHead>
                            <TableHead>CVE</TableHead>
                            <TableHead>CVSS</TableHead>
                            <TableHead>Target</TableHead>
                            <TableHead>Scope</TableHead>
                            <TableHead>Verification</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {filtered.map((finding) => (
                            <TableRow key={finding.id}>
                                <TableCell>
                                    <Badge className={severityClass[finding.severity]}>
                                        {severityLabel[finding.severity]}
                                    </Badge>
                                </TableCell>
                                <TableCell className="font-medium">{finding.title}</TableCell>
                                <TableCell className="font-mono text-xs">{finding.cve ?? '—'}</TableCell>
                                <TableCell className="text-xs">
                                    {finding.cvssScore != null ? finding.cvssScore.toFixed(1) : '—'}
                                </TableCell>
                                <TableCell className="font-mono text-xs">
                                    <span className="text-muted-foreground mr-1">{finding.target.kind.toLowerCase()}:</span>
                                    {finding.target.ref}
                                </TableCell>
                                <TableCell>
                                    {finding.inScope ? (
                                        <Badge variant="secondary">In</Badge>
                                    ) : (
                                        <Badge variant="outline">Out</Badge>
                                    )}
                                </TableCell>
                                <TableCell className="text-xs">
                                    {verificationLabel[finding.verificationStatus]}
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            )}
        </div>
    );
}
