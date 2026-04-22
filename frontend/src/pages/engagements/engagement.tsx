import { format } from 'date-fns';
import { GitFork, Loader2, ShieldCheck } from 'lucide-react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { Badge } from '@/components/ui/badge';
import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { StatusCard } from '@/components/ui/status-card';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
    EngagementStatus,
    ParseStatus,
    ScanSourceType,
    useEngagementQuery,
} from '@/graphql/types';
import { EngagementContextPill } from '@/pages/engagements/components/engagement-context-pill';
import { FindingsTable } from '@/pages/engagements/components/findings-table';
import { ScopeRuleEditor } from '@/pages/engagements/components/scope-rule-editor';
import { UploadDropzone } from '@/pages/engagements/components/upload-dropzone';

const statusVariant: Record<EngagementStatus, 'default' | 'destructive' | 'outline' | 'secondary'> = {
    [EngagementStatus.Active]: 'default',
    [EngagementStatus.Archived]: 'outline',
    [EngagementStatus.Completed]: 'secondary',
    [EngagementStatus.OnHold]: 'outline',
};

const statusLabel: Record<EngagementStatus, string> = {
    [EngagementStatus.Active]: 'Active',
    [EngagementStatus.Archived]: 'Archived',
    [EngagementStatus.Completed]: 'Completed',
    [EngagementStatus.OnHold]: 'On hold',
};

const parseStatusLabel: Record<ParseStatus, string> = {
    [ParseStatus.Failed]: 'Failed',
    [ParseStatus.Parsing]: 'Parsing',
    [ParseStatus.Partial]: 'Partial',
    [ParseStatus.Pending]: 'Pending',
    [ParseStatus.Succeeded]: 'Succeeded',
};

const parseStatusVariant: Record<ParseStatus, 'default' | 'destructive' | 'outline' | 'secondary'> = {
    [ParseStatus.Failed]: 'destructive',
    [ParseStatus.Parsing]: 'outline',
    [ParseStatus.Partial]: 'outline',
    [ParseStatus.Pending]: 'outline',
    [ParseStatus.Succeeded]: 'secondary',
};

const sourceTypeLabel: Record<ScanSourceType, string> = {
    [ScanSourceType.Burp]: 'Burp',
    [ScanSourceType.Nmap]: 'Nmap',
    [ScanSourceType.Qualys]: 'Qualys',
    [ScanSourceType.Twistlock]: 'Twistlock',
};

const Engagement = () => {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();

    const { data, error, loading, refetch } = useEngagementQuery({
        fetchPolicy: 'cache-and-network',
        skip: !id,
        variables: { id: id ?? '' },
    });

    const engagement = data?.engagement;

    const pageHeader = (
        <header className="bg-background sticky top-0 z-10 flex h-12 w-full shrink-0 items-center gap-2 border-b">
            <div className="flex items-center gap-2 px-4">
                <SidebarTrigger className="-ml-1" />
                <Separator
                    className="h-4"
                    orientation="vertical"
                />
                <Breadcrumb>
                    <BreadcrumbList>
                        <BreadcrumbItem>
                            <ShieldCheck className="size-4" />
                            <BreadcrumbLink asChild>
                                <Link to="/engagements">Engagements</Link>
                            </BreadcrumbLink>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbPage>{engagement?.name ?? 'Engagement'}</BreadcrumbPage>
                        </BreadcrumbItem>
                    </BreadcrumbList>
                </Breadcrumb>
            </div>
        </header>
    );

    if (loading && !data) {
        return (
            <>
                {pageHeader}
                <div className="flex flex-col gap-4 p-4">
                    <StatusCard
                        description="Fetching engagement details..."
                        icon={<Loader2 className="text-muted-foreground size-8 animate-spin" />}
                        title="Loading"
                    />
                </div>
            </>
        );
    }

    if (error) {
        return (
            <>
                {pageHeader}
                <div className="flex flex-col gap-4 p-4">
                    <StatusCard
                        description={error.message}
                        title="Failed to load engagement"
                    />
                </div>
            </>
        );
    }

    if (!engagement) {
        return (
            <>
                {pageHeader}
                <div className="flex flex-col gap-4 p-4">
                    <StatusCard
                        action={
                            <Button
                                onClick={() => navigate('/engagements')}
                                variant="secondary"
                            >
                                Back to engagements
                            </Button>
                        }
                        description="The engagement you requested could not be found."
                        title="Engagement not found"
                    />
                </div>
            </>
        );
    }

    return (
        <>
            {pageHeader}
            <div className="flex flex-col gap-4 p-4">
                <Card>
                    <CardContent className="flex flex-col gap-3 pt-6">
                        <div className="flex flex-wrap items-center gap-3">
                            <h1 className="text-2xl font-semibold">{engagement.name}</h1>
                            <Badge variant={statusVariant[engagement.status]}>
                                {statusLabel[engagement.status]}
                            </Badge>
                            <EngagementContextPill engagement={engagement} />
                        </div>
                        {engagement.description && (
                            <p className="text-muted-foreground text-sm whitespace-pre-wrap">
                                {engagement.description}
                            </p>
                        )}
                        <div className="text-muted-foreground flex flex-wrap gap-4 text-xs">
                            <span>Client: <span className="text-foreground">{engagement.client}</span></span>
                            <span>
                                Created: <span className="text-foreground">
                                    {format(new Date(engagement.createdAt), 'd MMM yyyy')}
                                </span>
                            </span>
                            <span>
                                Updated: <span className="text-foreground">
                                    {format(new Date(engagement.updatedAt), 'd MMM yyyy, HH:mm')}
                                </span>
                            </span>
                        </div>
                        <div className="flex flex-wrap gap-2 text-xs">
                            <Badge className="bg-red-600 text-white">
                                Critical: {engagement.findingStats.critical}
                            </Badge>
                            <Badge className="bg-orange-500 text-white">
                                High: {engagement.findingStats.high}
                            </Badge>
                            <Badge className="bg-yellow-500 text-black">
                                Medium: {engagement.findingStats.medium}
                            </Badge>
                            <Badge className="bg-blue-500 text-white">
                                Low: {engagement.findingStats.low}
                            </Badge>
                            <Badge variant="outline">Info: {engagement.findingStats.info}</Badge>
                            <Badge variant="secondary">
                                Confirmed: {engagement.findingStats.confirmed}
                            </Badge>
                            <Badge variant="outline">
                                Out of scope: {engagement.findingStats.outOfScope}
                            </Badge>
                        </div>
                    </CardContent>
                </Card>

                <Tabs
                    className="w-full"
                    defaultValue="reports"
                >
                    <TabsList>
                        <TabsTrigger value="reports">Reports ({engagement.scanReports.length})</TabsTrigger>
                        <TabsTrigger value="findings">Findings ({engagement.findings.length})</TabsTrigger>
                        <TabsTrigger value="flows">Flows</TabsTrigger>
                    </TabsList>

                    <TabsContent value="reports">
                        <Card>
                            <CardContent className="flex flex-col gap-6 pt-6">
                                <UploadDropzone
                                    engagementId={engagement.id}
                                    onUploaded={() => refetch()}
                                />

                                <Separator />

                                <div className="flex flex-col gap-4">
                                    <h3 className="text-sm font-semibold">Scan reports</h3>
                                    {engagement.scanReports.length === 0 ? (
                                        <div className="text-muted-foreground rounded-md border border-dashed p-4 text-center text-xs">
                                            No reports ingested yet.
                                        </div>
                                    ) : (
                                        <Table>
                                            <TableHeader>
                                                <TableRow>
                                                    <TableHead>Source</TableHead>
                                                    <TableHead>Filename</TableHead>
                                                    <TableHead>Status</TableHead>
                                                    <TableHead>Findings</TableHead>
                                                    <TableHead>Ingested</TableHead>
                                                </TableRow>
                                            </TableHeader>
                                            <TableBody>
                                                {engagement.scanReports.map((report) => (
                                                    <TableRow key={report.id}>
                                                        <TableCell>
                                                            <Badge variant="outline">
                                                                {sourceTypeLabel[report.sourceType]}
                                                            </Badge>
                                                        </TableCell>
                                                        <TableCell className="font-mono text-xs">
                                                            {report.originalFilename}
                                                        </TableCell>
                                                        <TableCell>
                                                            <Badge variant={parseStatusVariant[report.parseStatus]}>
                                                                {parseStatusLabel[report.parseStatus]}
                                                            </Badge>
                                                            {report.parseError && (
                                                                <div
                                                                    className="text-destructive mt-1 max-w-xs truncate text-xs"
                                                                    title={report.parseError}
                                                                >
                                                                    {report.parseError}
                                                                </div>
                                                            )}
                                                        </TableCell>
                                                        <TableCell className="text-xs">
                                                            {report.findingCount}
                                                        </TableCell>
                                                        <TableCell className="text-muted-foreground text-xs">
                                                            {format(
                                                                new Date(report.ingestedAt),
                                                                'd MMM yyyy, HH:mm',
                                                            )}
                                                        </TableCell>
                                                    </TableRow>
                                                ))}
                                            </TableBody>
                                        </Table>
                                    )}
                                </div>

                                <Separator />

                                <ScopeRuleEditor
                                    engagementId={engagement.id}
                                    rules={engagement.scopeRules}
                                />
                            </CardContent>
                        </Card>
                    </TabsContent>

                    <TabsContent value="findings">
                        <Card>
                            <CardContent className="pt-6">
                                <FindingsTable findings={engagement.findings} />
                            </CardContent>
                        </Card>
                    </TabsContent>

                    <TabsContent value="flows">
                        <Card>
                            <CardContent className="flex flex-col items-center gap-4 py-10 text-center">
                                <GitFork className="text-muted-foreground size-8" />
                                <div>
                                    <h3 className="text-lg font-semibold">Flows are not yet scoped to engagements</h3>
                                    <p className="text-muted-foreground mt-1 max-w-md text-sm">
                                        The flow <code>engagement_id</code> link is arriving in a follow-up.
                                        For now, start a regular pentest flow and reference this engagement manually.
                                    </p>
                                </div>
                                <Button
                                    onClick={() => navigate('/flows/new')}
                                    variant="secondary"
                                >
                                    <GitFork />
                                    Start a new flow
                                </Button>
                            </CardContent>
                        </Card>
                    </TabsContent>
                </Tabs>
            </div>
        </>
    );
};

export default Engagement;
