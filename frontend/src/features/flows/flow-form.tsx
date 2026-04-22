import { zodResolver } from '@hookform/resolvers/zod';
import { ArrowUp, Check, ChevronDown, FileSymlink, FileText, Square, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useRef } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';

import { ProviderIcon } from '@/components/icons/provider-icon';
import ConfirmationDialog from '@/components/shared/confirmation-dialog';
import { Badge } from '@/components/ui/badge';
import {
    DropdownMenu,
    DropdownMenuCheckboxItem,
    DropdownMenuContent,
    DropdownMenuGroup,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Form, FormControl, FormField, FormLabel } from '@/components/ui/form';
import {
    InputGroup,
    InputGroupAddon,
    InputGroupButton,
    InputGroupInput,
    InputGroupTextareaAutosize,
} from '@/components/ui/input-group';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Spinner } from '@/components/ui/spinner';
import { Switch } from '@/components/ui/switch';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import {
    FlowType,
    useEngagementQuery,
    useEngagementsQuery,
    useFlowsForBaselinePickerQuery,
} from '@/graphql/types';
import { getProviderDisplayName } from '@/models/provider';
import { EngagementContextPill } from '@/pages/engagements/components/engagement-context-pill';
import { useProviders } from '@/providers/providers-provider';
import { type Template, useTemplates } from '@/providers/templates-provider';

const NONE_ENGAGEMENT = '__none__';

const formSchema = z
    .object({
        baselineFlowId: z.string().optional(),
        engagementId: z.string().optional(),
        flowType: z.nativeEnum(FlowType).optional(),
        message: z.string().trim().min(1, { message: 'Message cannot be empty' }),
        providerName: z.string().trim().min(1, { message: 'Provider must be selected' }),
        retestTargetFindingIds: z.array(z.string()).optional(),
        useAgents: z.boolean(),
    })
    .superRefine((values, ctx) => {
        const flowType = values.flowType;
        const hasEngagement = Boolean(values.engagementId);
        const hasBaseline = Boolean(values.baselineFlowId);
        const hasFindings = (values.retestTargetFindingIds?.length ?? 0) > 0;

        // Any non-default flow type requires an engagement (mirrors server rule).
        if (!hasEngagement && flowType && flowType !== FlowType.NewTest) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'Select an engagement to use this flow type',
                path: ['flowType'],
            });
        }

        // Retest-specific args require an engagement too.
        if (!hasEngagement && (hasBaseline || hasFindings)) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'Retest arguments require an engagement',
                path: ['engagementId'],
            });
        }

        if (flowType === FlowType.RetestDiff && !hasBaseline) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'Select the baseline flow to compare against',
                path: ['baselineFlowId'],
            });
        }

        if (flowType === FlowType.TargetedReverify && !hasFindings) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'Select at least one finding to reverify',
                path: ['retestTargetFindingIds'],
            });
        }
    });

export interface FlowFormProps {
    defaultValues?: Partial<FlowFormValues>;
    isCanceling?: boolean;
    isDisabled?: boolean;
    isLoading?: boolean;
    isProviderDisabled?: boolean;
    isSubmitting?: boolean;
    onCancel?: () => Promise<void> | void;
    onSubmit: (values: FlowFormValues) => Promise<void> | void;
    placeholder?: string;
    type: 'assistant' | 'automation';
}

export type FlowFormValues = z.infer<typeof formSchema>;

export const FlowForm = ({
    defaultValues,
    isCanceling,
    isDisabled,
    isLoading,
    isProviderDisabled,
    isSubmitting,
    onCancel,
    onSubmit,
    placeholder = 'Describe what you would like PentAGI to test...',
    type,
}: FlowFormProps) => {
    const { providers, setSelectedProvider } = useProviders();
    const { templates } = useTemplates();
    const [isReplaceConfirmOpen, setIsReplaceConfirmOpen] = useState(false);
    const [pendingTemplate, setPendingTemplate] = useState<null | Template>(null);
    const [providerSearch, setProviderSearch] = useState('');
    const [templateSearch, setTemplateSearch] = useState('');

    const filteredTemplates = useMemo(() => {
        if (!templateSearch.trim()) {
            return templates;
        }

        const searchLower = templateSearch.toLowerCase();

        return templates.filter(
            (template) =>
                template.title.toLowerCase().includes(searchLower) || template.text.toLowerCase().includes(searchLower),
        );
    }, [templates, templateSearch]);

    const filteredProviders = useMemo(() => {
        if (!providerSearch.trim()) {
            return providers;
        }

        const searchLower = providerSearch.toLowerCase();

        return providers.filter((provider) => {
            const displayName = getProviderDisplayName(provider).toLowerCase();

            return displayName.includes(searchLower) || provider.name.toLowerCase().includes(searchLower);
        });
    }, [providers, providerSearch]);

    const form = useForm<FlowFormValues>({
        defaultValues: {
            baselineFlowId: defaultValues?.baselineFlowId ?? undefined,
            engagementId: defaultValues?.engagementId ?? undefined,
            flowType: defaultValues?.flowType ?? FlowType.NewTest,
            message: defaultValues?.message ?? '',
            providerName: defaultValues?.providerName ?? '',
            retestTargetFindingIds: defaultValues?.retestTargetFindingIds ?? [],
            useAgents: defaultValues?.useAgents ?? false,
        },
        mode: 'onChange',
        resolver: zodResolver(formSchema),
    });

    const {
        control,
        formState: { dirtyFields, isValid },
        getValues,
        handleSubmit: handleFormSubmit,
        resetField,
        setValue,
        watch,
    } = form;

    // Engagement-aware flow creation — these fields are optional; when no
    // engagement is selected, the form behaves exactly like the legacy path.
    const selectedEngagementId = watch('engagementId');
    const selectedFlowType = watch('flowType');
    const selectedBaselineFlowId = watch('baselineFlowId');
    const selectedFindingIds = watch('retestTargetFindingIds') ?? [];

    const { data: engagementsData, loading: engagementsLoading } = useEngagementsQuery({
        fetchPolicy: 'cache-and-network',
    });
    const engagements = useMemo(() => engagementsData?.engagements ?? [], [engagementsData]);

    const { data: engagementDetailData } = useEngagementQuery({
        fetchPolicy: 'cache-and-network',
        skip: !selectedEngagementId,
        variables: { id: selectedEngagementId ?? '' },
    });
    const selectedEngagement = engagementDetailData?.engagement ?? null;
    const engagementFindings = useMemo(
        () => (selectedEngagement?.findings ?? []).filter((finding) => finding.inScope),
        [selectedEngagement],
    );

    const { data: baselineFlowsData } = useFlowsForBaselinePickerQuery({
        fetchPolicy: 'cache-and-network',
        skip: !selectedEngagementId || selectedFlowType !== FlowType.RetestDiff,
    });
    const baselineFlows = useMemo(() => {
        if (!selectedEngagementId) {
            return [];
        }

        return (baselineFlowsData?.flows ?? []).filter(
            (flow) => flow.engagement?.id === selectedEngagementId,
        );
    }, [baselineFlowsData, selectedEngagementId]);

    // Update form values from defaultValues if user hasn't manually changed them
    useEffect(() => {
        if (!defaultValues) {
            return;
        }

        const currentValues = getValues();

        // Update only fields that user hasn't manually changed and that differ from current values
        Object.entries(defaultValues)
            .filter(([fieldName, defaultValue]) => {
                const typedFieldName = fieldName as keyof FlowFormValues;

                return (
                    defaultValue !== undefined &&
                    !dirtyFields[typedFieldName] &&
                    currentValues[typedFieldName] !== defaultValue
                );
            })
            .forEach(([fieldName, defaultValue]) => {
                const typedFieldName = fieldName as keyof FlowFormValues;
                setValue(typedFieldName, defaultValue as never, { shouldDirty: false });
            });
    }, [defaultValues, dirtyFields, setValue, getValues]);

    const isFormDisabled = isDisabled || isLoading || isSubmitting || isCanceling;

    const textareaRef = useRef<HTMLTextAreaElement>(null);
    const previousFormDisabledRef = useRef(isFormDisabled);

    useEffect(() => {
        const isDisabled = previousFormDisabledRef.current;
        previousFormDisabledRef.current = isFormDisabled;

        if (isDisabled && !isFormDisabled) {
            textareaRef.current?.focus();
        }
    }, [isFormDisabled]);

    const handleSubmit = async (values: FlowFormValues) => {
        await onSubmit(values);
        resetField('message');
    };

    const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
        const { ctrlKey, key, metaKey, shiftKey } = event;

        if (isFormDisabled || key !== 'Enter' || shiftKey || ctrlKey || metaKey) {
            return;
        }

        event.preventDefault();
        handleFormSubmit(handleSubmit)();
    };

    const handleApplyTemplate = useCallback(
        (template: Template) => {
            const currentMessage = getValues('message')?.trim() ?? '';

            if (currentMessage.length > 0) {
                setPendingTemplate(template);
                setIsReplaceConfirmOpen(true);
            } else {
                setValue('message', template.text, { shouldValidate: true });
                setTemplateSearch('');
            }
        },
        [getValues, setValue],
    );

    const handleConfirmReplaceTemplate = useCallback(() => {
        if (pendingTemplate) {
            setValue('message', pendingTemplate.text, { shouldValidate: true });
            setTemplateSearch('');
            setPendingTemplate(null);
        }
    }, [pendingTemplate, setValue]);

    return (
        <Form {...form}>
            <form onSubmit={handleFormSubmit(handleSubmit)}>
                <div className="mb-3 flex flex-col gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                        <FormField
                            control={control}
                            name="engagementId"
                            render={({ field }) => (
                                <FormControl>
                                    <Select
                                        disabled={isFormDisabled || engagementsLoading}
                                        onValueChange={(value) => {
                                            if (value === NONE_ENGAGEMENT) {
                                                field.onChange(undefined);
                                                // Reset retest-specific fields when clearing engagement.
                                                setValue('flowType', FlowType.NewTest, {
                                                    shouldDirty: true,
                                                    shouldValidate: true,
                                                });
                                                setValue('baselineFlowId', undefined, {
                                                    shouldDirty: true,
                                                    shouldValidate: true,
                                                });
                                                setValue('retestTargetFindingIds', [], {
                                                    shouldDirty: true,
                                                    shouldValidate: true,
                                                });
                                            } else {
                                                field.onChange(value);
                                            }
                                        }}
                                        value={field.value ?? NONE_ENGAGEMENT}
                                    >
                                        <SelectTrigger className="w-56">
                                            <SelectValue placeholder="No engagement (ad-hoc)" />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value={NONE_ENGAGEMENT}>
                                                No engagement (ad-hoc)
                                            </SelectItem>
                                            {engagements.map((engagement) => (
                                                <SelectItem
                                                    key={engagement.id}
                                                    value={engagement.id}
                                                >
                                                    {engagement.name} — {engagement.client}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                </FormControl>
                            )}
                        />
                        {selectedEngagement && (
                            <EngagementContextPill
                                engagement={{
                                    client: selectedEngagement.client,
                                    name: selectedEngagement.name,
                                }}
                            />
                        )}
                    </div>

                    {selectedEngagementId && (
                        <>
                            <FormField
                                control={control}
                                name="flowType"
                                render={({ field }) => (
                                    <FormControl>
                                        <ToggleGroup
                                            className="justify-start"
                                            disabled={isFormDisabled}
                                            onValueChange={(value) => {
                                                if (!value) {
                                                    return;
                                                }

                                                field.onChange(value as FlowType);

                                                // Clear dependent fields when switching types.
                                                if (value !== FlowType.RetestDiff) {
                                                    setValue('baselineFlowId', undefined, {
                                                        shouldDirty: true,
                                                        shouldValidate: true,
                                                    });
                                                }

                                                if (value !== FlowType.TargetedReverify) {
                                                    setValue('retestTargetFindingIds', [], {
                                                        shouldDirty: true,
                                                        shouldValidate: true,
                                                    });
                                                }
                                            }}
                                            size="sm"
                                            type="single"
                                            value={field.value ?? FlowType.NewTest}
                                            variant="outline"
                                        >
                                            <ToggleGroupItem value={FlowType.NewTest}>
                                                New test
                                            </ToggleGroupItem>
                                            <ToggleGroupItem value={FlowType.RetestDiff}>
                                                Retest diff
                                            </ToggleGroupItem>
                                            <ToggleGroupItem value={FlowType.TargetedReverify}>
                                                Targeted reverify
                                            </ToggleGroupItem>
                                        </ToggleGroup>
                                    </FormControl>
                                )}
                            />

                            {selectedFlowType === FlowType.RetestDiff && (
                                <FormField
                                    control={control}
                                    name="baselineFlowId"
                                    render={({ field }) => (
                                        <FormControl>
                                            <Select
                                                disabled={isFormDisabled || baselineFlows.length === 0}
                                                onValueChange={field.onChange}
                                                value={field.value ?? ''}
                                            >
                                                <SelectTrigger className="w-full">
                                                    <SelectValue
                                                        placeholder={
                                                            baselineFlows.length === 0
                                                                ? 'No prior flows on this engagement'
                                                                : 'Select baseline flow…'
                                                        }
                                                    />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    {baselineFlows.map((flow) => (
                                                        <SelectItem
                                                            key={flow.id}
                                                            value={flow.id}
                                                        >
                                                            {flow.title || `Flow ${flow.id}`}
                                                        </SelectItem>
                                                    ))}
                                                </SelectContent>
                                            </Select>
                                        </FormControl>
                                    )}
                                />
                            )}

                            {selectedFlowType === FlowType.TargetedReverify && (
                                <FormField
                                    control={control}
                                    name="retestTargetFindingIds"
                                    render={({ field }) => {
                                        const selected: string[] = field.value ?? [];

                                        const toggle = (id: string, checked: boolean) => {
                                            const next = checked
                                                ? Array.from(new Set([id, ...selected]))
                                                : selected.filter((existing) => existing !== id);
                                            field.onChange(next);
                                        };

                                        return (
                                            <FormControl>
                                                <DropdownMenu>
                                                    <DropdownMenuTrigger asChild>
                                                        <InputGroupButton
                                                            className="w-full justify-between"
                                                            disabled={
                                                                isFormDisabled ||
                                                                engagementFindings.length === 0
                                                            }
                                                            variant="outline"
                                                        >
                                                            <span className="truncate">
                                                                {selected.length === 0
                                                                    ? engagementFindings.length === 0
                                                                        ? 'No in-scope findings'
                                                                        : 'Select findings to reverify…'
                                                                    : `${selected.length} finding${
                                                                          selected.length === 1 ? '' : 's'
                                                                      } selected`}
                                                            </span>
                                                            <ChevronDown />
                                                        </InputGroupButton>
                                                    </DropdownMenuTrigger>
                                                    <DropdownMenuContent
                                                        align="start"
                                                        className="max-h-80 w-[28rem] overflow-y-auto"
                                                    >
                                                        {engagementFindings.length === 0 ? (
                                                            <DropdownMenuItem
                                                                className="justify-center"
                                                                disabled
                                                            >
                                                                No in-scope findings
                                                            </DropdownMenuItem>
                                                        ) : (
                                                            engagementFindings.map((finding) => {
                                                                const isChecked = selected.includes(finding.id);

                                                                return (
                                                                    <DropdownMenuCheckboxItem
                                                                        checked={isChecked}
                                                                        key={finding.id}
                                                                        onCheckedChange={(checked) =>
                                                                            toggle(finding.id, Boolean(checked))
                                                                        }
                                                                        onSelect={(event) => event.preventDefault()}
                                                                    >
                                                                        <div className="flex min-w-0 flex-col gap-0.5">
                                                                            <span className="truncate text-sm">
                                                                                {finding.title}
                                                                            </span>
                                                                            <div className="text-muted-foreground flex flex-wrap items-center gap-1 text-xs">
                                                                                <Badge
                                                                                    className="px-1 py-0 text-[10px]"
                                                                                    variant="secondary"
                                                                                >
                                                                                    {finding.severity}
                                                                                </Badge>
                                                                                {finding.cve && (
                                                                                    <span>{finding.cve}</span>
                                                                                )}
                                                                                <span className="truncate">
                                                                                    {finding.target.ref}
                                                                                </span>
                                                                            </div>
                                                                        </div>
                                                                    </DropdownMenuCheckboxItem>
                                                                );
                                                            })
                                                        )}
                                                    </DropdownMenuContent>
                                                </DropdownMenu>
                                            </FormControl>
                                        );
                                    }}
                                />
                            )}
                        </>
                    )}
                </div>

                <FormField
                    control={control}
                    name="message"
                    render={({ field }) => (
                        <FormControl>
                            <InputGroup className="block">
                                <InputGroupTextareaAutosize
                                    {...field}
                                    autoFocus
                                    className="min-h-0"
                                    disabled={isFormDisabled}
                                    maxRows={9}
                                    minRows={1}
                                    onKeyDown={handleKeyDown}
                                    placeholder={placeholder}
                                    ref={(element) => {
                                        field.ref(element);
                                        textareaRef.current = element;
                                    }}
                                />
                                <InputGroupAddon align="block-end">
                                    <FormField
                                        control={control}
                                        name="providerName"
                                        render={({ field: providerField }) => {
                                            const currentProvider = providers.find(
                                                (p) => p.name === providerField.value,
                                            );

                                            return (
                                                <DropdownMenu>
                                                    <DropdownMenuTrigger asChild>
                                                        <InputGroupButton
                                                            disabled={isFormDisabled || isProviderDisabled}
                                                            variant="ghost"
                                                        >
                                                            {currentProvider && (
                                                                <ProviderIcon provider={currentProvider} />
                                                            )}
                                                            <span className="max-w-40 truncate">
                                                                {currentProvider
                                                                    ? getProviderDisplayName(currentProvider)
                                                                    : 'Select Provider'}
                                                            </span>
                                                            <ChevronDown />
                                                        </InputGroupButton>
                                                    </DropdownMenuTrigger>
                                                    <DropdownMenuContent
                                                        align="start"
                                                        side="top"
                                                    >
                                                        <DropdownMenuGroup className="-m-1 rounded-none p-0">
                                                            <InputGroup className="-mb-1 rounded-none border-0 shadow-none [&:has([data-slot=input-group-control]:focus-visible)]:border-0 [&:has([data-slot=input-group-control]:focus-visible)]:ring-0">
                                                                <InputGroupInput
                                                                    onChange={(event) =>
                                                                        setProviderSearch(event.target.value)
                                                                    }
                                                                    onClick={(event) => event.stopPropagation()}
                                                                    onKeyDown={(event) => event.stopPropagation()}
                                                                    placeholder="Search..."
                                                                    value={providerSearch}
                                                                />
                                                                {providerSearch && (
                                                                    <InputGroupAddon align="inline-end">
                                                                        <InputGroupButton
                                                                            onClick={(event) => {
                                                                                event.stopPropagation();
                                                                                setProviderSearch('');
                                                                            }}
                                                                        >
                                                                            <X />
                                                                        </InputGroupButton>
                                                                    </InputGroupAddon>
                                                                )}
                                                            </InputGroup>
                                                            <DropdownMenuSeparator />
                                                        </DropdownMenuGroup>
                                                        <DropdownMenuGroup className="max-h-64 overflow-y-auto">
                                                            {!filteredProviders.length ? (
                                                                <DropdownMenuItem
                                                                    className="min-h-16 justify-center"
                                                                    disabled
                                                                >
                                                                    {providerSearch
                                                                        ? 'No results found'
                                                                        : 'No available providers'}
                                                                </DropdownMenuItem>
                                                            ) : (
                                                                filteredProviders.map((provider) => (
                                                                    <DropdownMenuItem
                                                                        key={provider.name}
                                                                        onSelect={() => {
                                                                            if (isFormDisabled || isProviderDisabled) {
                                                                                return;
                                                                            }

                                                                            providerField.onChange(provider.name);
                                                                            setSelectedProvider(provider);
                                                                            setProviderSearch('');
                                                                        }}
                                                                    >
                                                                        <div className="flex w-full min-w-0 items-center gap-2">
                                                                            <ProviderIcon
                                                                                className="size-4 shrink-0"
                                                                                provider={provider}
                                                                            />

                                                                            <span className="flex-1 truncate">
                                                                                {getProviderDisplayName(provider)}
                                                                            </span>
                                                                            {providerField.value === provider.name && (
                                                                                <Check className="ml-auto size-4 shrink-0" />
                                                                            )}
                                                                        </div>
                                                                    </DropdownMenuItem>
                                                                ))
                                                            )}
                                                        </DropdownMenuGroup>
                                                    </DropdownMenuContent>
                                                </DropdownMenu>
                                            );
                                        }}
                                    />

                                    {type === 'assistant' && (
                                        <FormField
                                            control={control}
                                            name="useAgents"
                                            render={({ field: useAgentsField }) => (
                                                <TooltipProvider>
                                                    <Tooltip>
                                                        <TooltipTrigger asChild>
                                                            <div className="flex items-center">
                                                                <FormControl>
                                                                    <Switch
                                                                        checked={useAgentsField.value}
                                                                        disabled={isFormDisabled}
                                                                        onCheckedChange={useAgentsField.onChange}
                                                                    />
                                                                </FormControl>
                                                                <FormLabel
                                                                    className="flex cursor-pointer pl-2 text-xs font-normal"
                                                                    onClick={() =>
                                                                        useAgentsField.onChange(!useAgentsField.value)
                                                                    }
                                                                >
                                                                    Use Agents
                                                                </FormLabel>
                                                            </div>
                                                        </TooltipTrigger>
                                                        <TooltipContent>
                                                            <p className="max-w-48">
                                                                Enable multi-agent collaboration for complex tasks
                                                            </p>
                                                        </TooltipContent>
                                                    </Tooltip>
                                                </TooltipProvider>
                                            )}
                                        />
                                    )}

                                    <DropdownMenu>
                                        <DropdownMenuTrigger asChild>
                                            <InputGroupButton
                                                disabled={isFormDisabled}
                                                variant="ghost"
                                            >
                                                <FileText className="shrink-0" />
                                                <ChevronDown />
                                            </InputGroupButton>
                                        </DropdownMenuTrigger>
                                        <DropdownMenuContent
                                            align="start"
                                            side="top"
                                        >
                                            <DropdownMenuGroup className="-m-1 rounded-none p-0">
                                                <InputGroup className="-mb-1 rounded-none border-0 shadow-none [&:has([data-slot=input-group-control]:focus-visible)]:border-0 [&:has([data-slot=input-group-control]:focus-visible)]:ring-0">
                                                    <InputGroupInput
                                                        onChange={(event) => setTemplateSearch(event.target.value)}
                                                        onClick={(event) => event.stopPropagation()}
                                                        onKeyDown={(event) => event.stopPropagation()}
                                                        placeholder="Search..."
                                                        value={templateSearch}
                                                    />
                                                    {templateSearch && (
                                                        <InputGroupAddon align="inline-end">
                                                            <InputGroupButton
                                                                onClick={(event) => {
                                                                    event.stopPropagation();
                                                                    setTemplateSearch('');
                                                                }}
                                                            >
                                                                <X />
                                                            </InputGroupButton>
                                                        </InputGroupAddon>
                                                    )}
                                                </InputGroup>
                                                <DropdownMenuSeparator />
                                            </DropdownMenuGroup>
                                            <DropdownMenuGroup className="max-h-64 overflow-y-auto">
                                                {!filteredTemplates.length ? (
                                                    <DropdownMenuItem
                                                        className="min-h-16 justify-center"
                                                        disabled
                                                    >
                                                        {templateSearch ? 'No results found' : 'No available templates'}
                                                    </DropdownMenuItem>
                                                ) : (
                                                    filteredTemplates.map((template) => (
                                                        <DropdownMenuItem
                                                            key={template.id}
                                                            onSelect={() => {
                                                                if (isFormDisabled) {
                                                                    return;
                                                                }

                                                                handleApplyTemplate(template);
                                                            }}
                                                        >
                                                            <span className="max-w-80 flex-1 truncate">
                                                                {template.title}
                                                            </span>
                                                        </DropdownMenuItem>
                                                    ))
                                                )}
                                            </DropdownMenuGroup>
                                        </DropdownMenuContent>
                                    </DropdownMenu>

                                    {!isLoading || isSubmitting ? (
                                        (() => {
                                            // Build a human-readable reason for the tooltip when submit is disabled.
                                            let disabledReason = '';

                                            if (selectedEngagementId) {
                                                if (selectedFlowType === FlowType.RetestDiff && !selectedBaselineFlowId) {
                                                    disabledReason = 'Select a baseline flow to compare against';
                                                } else if (
                                                    selectedFlowType === FlowType.TargetedReverify &&
                                                    selectedFindingIds.length === 0
                                                ) {
                                                    disabledReason = 'Select at least one finding to reverify';
                                                }
                                            }

                                            const isDisabled = isSubmitting || !isValid;
                                            const button = (
                                                <InputGroupButton
                                                    className="ml-auto"
                                                    disabled={isDisabled}
                                                    size="icon-xs"
                                                    type="submit"
                                                    variant="default"
                                                >
                                                    {isSubmitting ? <Spinner variant="circle" /> : <ArrowUp />}
                                                </InputGroupButton>
                                            );

                                            if (!isDisabled || !disabledReason) {
                                                return button;
                                            }

                                            return (
                                                <TooltipProvider>
                                                    <Tooltip>
                                                        <TooltipTrigger asChild>
                                                            <span className="ml-auto">{button}</span>
                                                        </TooltipTrigger>
                                                        <TooltipContent>
                                                            <p className="max-w-56">{disabledReason}</p>
                                                        </TooltipContent>
                                                    </Tooltip>
                                                </TooltipProvider>
                                            );
                                        })()
                                    ) : (
                                        <InputGroupButton
                                            className="ml-auto"
                                            disabled={isCanceling || !onCancel}
                                            onClick={() => onCancel?.()}
                                            size="icon-xs"
                                            type="button"
                                            variant="destructive"
                                        >
                                            {isCanceling ? <Spinner variant="circle" /> : <Square />}
                                        </InputGroupButton>
                                    )}
                                </InputGroupAddon>
                            </InputGroup>
                        </FormControl>
                    )}
                />
            </form>
            <ConfirmationDialog
                confirmIcon={<FileSymlink />}
                confirmText="Replace"
                confirmVariant="default"
                description="Current message has content. Replace with the selected template?"
                handleConfirm={handleConfirmReplaceTemplate}
                handleOpenChange={(open) => {
                    if (!open) {
                        setPendingTemplate(null);
                    }

                    setIsReplaceConfirmOpen(open);
                }}
                isOpen={isReplaceConfirmOpen}
                title="Replace content?"
            />
        </Form>
    );
};
