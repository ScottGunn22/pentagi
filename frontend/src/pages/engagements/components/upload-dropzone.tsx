import { UploadCloud } from 'lucide-react';
import { type ChangeEvent, type DragEvent, useCallback, useRef, useState } from 'react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';

export type ScanSource = 'burp' | 'nmap' | 'qualys' | 'twistlock';

const SOURCES: { label: string; value: ScanSource }[] = [
    { label: 'Nmap (XML)', value: 'nmap' },
    { label: 'Burp Suite (XML)', value: 'burp' },
    { label: 'Twistlock / Prisma (JSON)', value: 'twistlock' },
    { label: 'Qualys (CSV)', value: 'qualys' },
];

const guessSourceFromExtension = (filename: string): ScanSource => {
    const lower = filename.toLowerCase();

    if (lower.endsWith('.json')) {
        return 'twistlock';
    }

    if (lower.endsWith('.csv')) {
        return 'qualys';
    }

    // default to nmap for .xml and anything else
    return 'nmap';
};

interface UploadDropzoneProps {
    engagementId: string;
    onUploaded?: () => void;
}

export function UploadDropzone({ engagementId, onUploaded }: UploadDropzoneProps) {
    const inputRef = useRef<HTMLInputElement>(null);
    const [file, setFile] = useState<File | null>(null);
    const [sourceType, setSourceType] = useState<ScanSource>('nmap');
    const [isDragging, setIsDragging] = useState(false);
    const [isUploading, setIsUploading] = useState(false);

    const applyFile = useCallback((next: File) => {
        setFile(next);
        setSourceType(guessSourceFromExtension(next.name));
    }, []);

    const handleSelect = useCallback(
        (event: ChangeEvent<HTMLInputElement>) => {
            const next = event.target.files?.[0];

            if (next) {
                applyFile(next);
            }
        },
        [applyFile],
    );

    const handleDrop = useCallback(
        (event: DragEvent<HTMLDivElement>) => {
            event.preventDefault();
            event.stopPropagation();
            setIsDragging(false);

            const next = event.dataTransfer.files?.[0];

            if (next) {
                applyFile(next);
            }
        },
        [applyFile],
    );

    const handleUpload = useCallback(async () => {
        if (!file || isUploading) {
            return;
        }

        setIsUploading(true);

        try {
            const body = new FormData();
            body.append('source_type', sourceType);
            body.append('file', file);

            const response = await fetch(`/api/v1/engagements/${engagementId}/reports`, {
                body,
                credentials: 'include',
                method: 'POST',
            });

            if (!response.ok) {
                const text = await response.text();
                throw new Error(text || `Upload failed with status ${response.status}`);
            }

            toast.success('Report uploaded and queued for parsing');
            setFile(null);

            if (inputRef.current) {
                inputRef.current.value = '';
            }

            onUploaded?.();
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Upload failed';
            toast.error(message);
        } finally {
            setIsUploading(false);
        }
    }, [engagementId, file, isUploading, onUploaded, sourceType]);

    return (
        <div className="flex flex-col gap-3">
            <div
                aria-label="Upload scanner report"
                className={cn(
                    'border-input flex flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed p-8 text-center transition-colors',
                    isDragging && 'border-primary bg-muted/50',
                )}
                onClick={() => inputRef.current?.click()}
                onDragLeave={(event) => {
                    event.preventDefault();
                    setIsDragging(false);
                }}
                onDragOver={(event) => {
                    event.preventDefault();
                    setIsDragging(true);
                }}
                onDrop={handleDrop}
                onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        inputRef.current?.click();
                    }
                }}
                role="button"
                tabIndex={0}
            >
                <UploadCloud className="text-muted-foreground size-8" />
                <div className="text-sm">
                    <span className="font-medium">Drop a scanner report here</span>
                    <span className="text-muted-foreground"> or click to browse</span>
                </div>
                <p className="text-muted-foreground text-xs">Supports Nmap XML, Burp XML, Twistlock JSON, Qualys CSV</p>
                <input
                    accept=".xml,.json,.csv"
                    className="hidden"
                    onChange={handleSelect}
                    ref={inputRef}
                    type="file"
                />
            </div>
            {file && (
                <div className="bg-muted/40 flex flex-col gap-3 rounded-md border p-3 sm:flex-row sm:items-center">
                    <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium">{file.name}</div>
                        <div className="text-muted-foreground text-xs">{(file.size / 1024).toFixed(1)} KB</div>
                    </div>
                    <div className="flex items-center gap-2">
                        <Select
                            onValueChange={(value) => setSourceType(value as ScanSource)}
                            value={sourceType}
                        >
                            <SelectTrigger className="w-48">
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                {SOURCES.map((source) => (
                                    <SelectItem
                                        key={source.value}
                                        value={source.value}
                                    >
                                        {source.label}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                        <Button
                            disabled={isUploading}
                            onClick={handleUpload}
                            type="button"
                        >
                            {isUploading ? 'Uploading...' : 'Upload'}
                        </Button>
                        <Button
                            disabled={isUploading}
                            onClick={() => {
                                setFile(null);

                                if (inputRef.current) {
                                    inputRef.current.value = '';
                                }
                            }}
                            type="button"
                            variant="ghost"
                        >
                            Cancel
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );
}
